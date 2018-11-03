from pyCat.hashcat import Hashcat, HC_EXIT_STATUS
from threading import Thread, Lock
from time import sleep
from queue import Queue
from enum import Enum
from sys import exit
from pyCat import args
from pexpect.exceptions import ExceptionPexpect, TIMEOUT
from random import randint

try:
    from mpi4py import MPI

except Exception as e:
    print(" 'mpi4py' module has not been found",  str(e))
    exit(-1)


class TAG(Enum):

    TAG_EXIT = 1  # Application exit
    TAG_STATUS = 2  # Hashcat job status
    TAG_CRACKED = 3  # Cracked
    TAG_ALL_FINISHED = 4  # All Queue Finished
    TAG_OUTFILE = 5  # Ask for outfile to slave
    TAG_BENCHMARK = 6  # get Benchmark
    TAG_ABORT = 7  # Abort current job
    TAG_COMMAND = 8  # Send command to slave and receive its result
    TAG_JOB_FINISHED = 9  # send last status when job finished
    TAG_QUIT = 10  # send Quit signal to slaves
    TAG_INFO = 11  # get info from Slave
    TAG_GET_HC = 12 # get hashcat job lis
    TAG_ERROR = 101  # Send Error message when occured


class Info:

    def __init__(self, job_count, fin_count, abort_job, current_command, job_id=-1, wstatus='NOT WORKING'):
        self.unfinished_job_count = job_count + 1
        self.processor_name = MPI.Get_processor_name()
        self.rank = MPI.COMM_WORLD.Get_rank()
        self.finished_job_count = fin_count
        self.aborted_job = abort_job
        self.current_command = current_command
        self.current_job_id = job_id
        self.wstatus = wstatus


class Client(Thread):

    master_rank = 0 #Global master rank

    def __init__(self, mpi, q: Queue, benchmark_score: int=50, outfile_chk_dir='./'):
        Thread.__init__(self)
        self.jobQ = q
        self.mpi = mpi
        self.current_job = None
        self.job_done = 0
        self.job_bugy = 0
        self.benchmark_score = benchmark_score
        self.mutex = Lock()
        self.is_client_up = False
        self.flag = False
        self.outfile_chk_dir = outfile_chk_dir
        #self.current_job.start()

    def run(self):
        self.is_client_up = True
        try:
            quitter = Thread(target=self.quitter_thread, args=())
            quitter.setDaemon(True)
            receiver = Thread(target=self.slave_receive_hcs, args=())
            quitter.start()
            receiver.setDaemon(True)
            receiver.start() # wait reveiver
            while self.is_client_up:
                while self.jobQ.empty():
                    sleep(0.2)
                    #print("empty", self.jobQ.empty())
                self.current_job = self.jobQ.get()
                #self.jobQ.join()
                self.current_job.invoke_after_termination = (lambda h: (self.hashcat_proc_end(h)))
                self.current_job.session = self.getName()
                #self.current_job.outfile_path += self.getName()
                self.current_job.outfile_check_dir = self.outfile_chk_dir
                self.flag = True
                tasks = []
                for task in (self.send_status_thread, self.send_info_thread, self.command_thread,
                             self.slave_send_outfile):
                    t = Thread(target=task, args=())
                    t.setDaemon(True)
                    tasks.append(t)
                self.current_job.start()
                for thread in tasks:
                    thread.start()
                self.current_job.join()
                if self.current_job.get_exit_status() in (HC_EXIT_STATUS.CRACKED, HC_EXIT_STATUS.EXHAUSTED,
                                                          HC_EXIT_STATUS):
                    self.job_done += 1
                else:
                    self.job_bugy += 1

        except Exception as ex:
            print("Client Runner Error", str(ex))
        finally:
            print("End of Client Process!")

    def send_status_thread(self):
        while self.flag:
            try:
                req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_STATUS.value, source=Client.master_rank)
                req.wait()
                hc_status = self.current_job.get_hc_state()
                self.mpi.send(hc_status, Client.master_rank, TAG.TAG_STATUS.value)
            except Exception as e:
                self.send_error('sender error ', e)

            finally:
                sleep(0.1)

    def send_error(self, msg: str, es: Exception):

        try:
            self.mpi.send("Rank" + str(MPI.COMM_WORLD.Get_rank())+" -> " + msg + str(es), Client.master_rank,
                          TAG.TAG_ERROR.value)

        except Exception as ep:
            print(ep)

    def command_thread(self):
        while self.flag:
            try:
                command = MPI.COMM_WORLD.recv(tag=TAG.TAG_COMMAND.value, source=Client.master_rank)
                response = self.current_job.cmd(command)
                MPI.COMM_WORLD.send(response, Client.master_rank, TAG.TAG_COMMAND.value)
            except Exception as e:
                self.send_error('Commander Thread', e)

    def send_info_thread(self):
        try:
            while self.is_client_up:
                req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_INFO.value, source=Client.master_rank)
                req.wait()
                wstatus = 'HASHCAT PROCESS NOT RUNNING'
                if self.current_job.get_exit_status() == HC_EXIT_STATUS.NON_EXIT:
                        wstatus = 'HASHCAT PROCESS RUNNING'
                info = Info(self.jobQ.qsize(), self.job_done, self.job_bugy, self.current_job.build_command(),
                            self.current_job.job_id,wstatus)
                MPI.COMM_WORLD.send(info, Client.master_rank, TAG.TAG_INFO.value)
        except Exception as ep1:
            self.send_error("info thread", ep1)

    def send_hashcat_exit(self, status: HC_EXIT_STATUS):
        try:
            MPI.COMM_WORLD.send(status, Client.master_rank, TAG.TAG_EXIT.value)
        except Exception as e:
            self.send_error('exit thread error', e)

    def quitter_thread(self):
        while self.is_client_up:
            try:
                MPI.COMM_WORLD.recv(tag=TAG.TAG_QUIT.value, source=Client.master_rank)

                self.current_job.cmd('q')
            except Exception as e6:
                self.send_error('Commander Thread', e6)
            finally:
                sleep(0.2)

    def send_benchmark_score(self):
        try:
            MPI.COMM_WORLD.send(self.benchmark_score, Client.master_rank, TAG.TAG_BENCHMARK.value)
        except Exception as e1:
            self.send_error("Sending benchmark score error", e1)

    def slave_receive_hcs(self):
        while self.is_client_up:
            try:
                req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_GET_HC.value, source=Client.master_rank)
                hc_obj = req.wait()
                hc = Hashcat.combine_from_object(hc_obj, args.Config.exec_path, args.Config.outfile_path)
                self.jobQ.put(hc)
                #print("SLAVE REVEIVED ", hc)
            except Exception as e1:
                self.send_error("Error at recv joblist", e1)
            finally:
                sleep(0.2)

    @staticmethod
    def is_slave():
        return MPI.COMM_WORLD.Get_rank() != Client.master_rank

    def slave_send_outfile(self):
        while self.is_client_up:
            lines = []
            req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_OUTFILE.value, source=Client.master_rank)
            req.wait()
            with open(self.current_job.outfile_path, "r") as f:
                for line in f:
                    lines.append(line)

            MPI.COMM_WORLD.send(lines, Client.master_rank, TAG.TAG_OUTFILE.value)

    def hashcat_proc_end(self, h: Hashcat):

        try:
            req = MPI.COMM_WORLD.isend((h.get_hc_state(), h.get_exit_status(), MPI.COMM_WORLD.Get_rank()),
                                   Client.master_rank, TAG.TAG_JOB_FINISHED.value)
            #req.Cancel()
            req.wait()
            self.jobQ.task_done()
        except TIMEOUT as to:
            self.send_error("proc_end()->Timeout", to)
        except Exception as exc1:
            self.send_error("proc_end", exc1)
