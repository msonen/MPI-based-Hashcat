from mpi4py import MPI
from pyCat.client import TAG
from pyCat.utils import Colors, c_out
from pyCat.hashcat import HC_EXIT_STATUS
from threading import Thread


def task_job_finished_receiver(size=None):
    while True:
        try:
            req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_JOB_FINISHED.value, source=MPI.ANY_SOURCE)
            data = req.wait()
            c_out("---> JOB FINISHED <----", Colors.HEADER)
            c_out("Rank: " + str(data[2]), Colors.BOLD)
            c_out("Exit Status: " + Colors.OKGREEN + str(data[1]), Colors.OKBLUE)
            if data[1] in (HC_EXIT_STATUS.ERROR, HC_EXIT_STATUS.BAD_ARGUMETNS):
                c_out("[ERROR] " + "Incorrect parameters", Colors.FAIL)
            #else:
             #   c_out(str(data[0]), Colors.HEADER)
            if data[1] == HC_EXIT_STATUS.CRACKED:
                size = MPI.COMM_WORLD.Get_rank()
                c_out("cracked_state",Colors.BOLD)
                for r in range(0, size):
                    if r == data[2]:
                        continue
                    #Thread(target=MPI.COMM_WORLD.send, args=(None, r, TAG.TAG_QUIT.value, )).start()

            c_out("-"*100, Colors.BOLD+Colors.WARNING)
        except Exception as e:
            print("Exception Occured While receiving data, task_job_receiver", e)


def task_catch_error():
    while True:
        try:
            req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_ERROR.value, source=MPI.ANY_SOURCE)
            data = req.wait()
            c_out("[ERROR] "+str(data), Colors.FAIL)
        except Exception as e:
            c_out("[ERROR] at task_cath_error()"+str(e), Colors.FAIL)


def task_ask_status(rank):

    try:
        MPI.COMM_WORLD.send(None, rank, TAG.TAG_STATUS.value)
        req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_STATUS.value, source=rank)
        data = req.wait()
        c_out("Rank: {:d}".format(rank), Colors.HEADER)
        c_out(str(data), Colors.OKGREEN)
        c_out("." * 50, Colors.OKGREEN)

    except MPI.Exception as ex:
        c_out("Exception in MPI " + str(ex), Colors.FAIL)
    except Exception as e:
        c_out("Thread ask_satus failed, " + str(e), Colors.FAIL)


def task_ask_info(rank):
    try:
        MPI.COMM_WORLD.send(None, rank, TAG.TAG_INFO.value)
        req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_INFO.value, source=rank)
        data = req.wait()
        c_out("INFO DATA".center(50, '.'), Colors.OKBLUE)
        c_out("Rank: {:d}  Host: {:s}".format(rank, data.processor_name), Colors.HEADER)
        c_out("Host Status".ljust(25)+":" + Colors.OKGREEN + data.wstatus, Colors.WARNING)
        c_out("Current Job ID".ljust(25)+":" + Colors.OKGREEN + str(data.current_job_id), Colors.WARNING)
        c_out("Finished Job  Count".ljust(25)+":" + Colors.OKGREEN + str(data.finished_job_count), Colors.WARNING)
        c_out("Un-Finished Job  Count".ljust(25)+":" + Colors.OKGREEN + str(data.unfinished_job_count), Colors.WARNING)
        c_out("Aborted Job  Count".ljust(25)+":" + Colors.OKGREEN + str(data.aborted_job), Colors.WARNING)
        c_out("Current Command".ljust(25)+":" + Colors.OKGREEN + str(data.current_command), Colors.WARNING)
        c_out("-" * 50, Colors.OKBLUE)

    except MPI.Exception as ex:
        c_out("Exception in MPI", Colors.FAIL)
    except Exception as e:
        c_out("Thread ask_info failed "+str(e), Colors.FAIL)


def task_command(cmd, rank):
    try:
        MPI.COMM_WORLD.send(cmd, rank, TAG.TAG_COMMAND.value)
        req = MPI.COMM_WORLD.irecv(tag=TAG.TAG_COMMAND.value, source=rank)
        data = req.wait()
        c_out("Command".center(50, '.'), Colors.OKBLUE)
        c_out("Rank: {:d}".format(rank), Colors.HEADER)
        c_out("Command Respond: ".ljust(25), Colors.OKGREEN)
        c_out(str(data), Colors.WARNING)
        c_out("-" * 50, Colors.OKBLUE)

    except MPI.Exception as ex:
        c_out("Exception in MPI "+str(ex), Colors.FAIL)
    except Exception as e:
        c_out("Thread task_command failed, "+str(e), Colors.FAIL)


def task_quit_current(size, rank=None):
    try:
        chunks = []
        if rank is not None:
            chunks.extend(rank)
        else:
            chunks.extend(range(0, size))
        for i in chunks:
            MPI.COMM_WORLD.send(None, i, TAG.TAG_QUIT.value)
            c_out("Quit Signal passed to Rank {:d}".format(i), Colors.WARNING)

    except MPI.Exception as ex:
        c_out("Exception in MPI", Colors.FAIL)
    except Exception as e:
        c_out("Thread ask_info failed", Colors.FAIL)


def task_send_newcmd(hc_obj, rank):
    try:
        req = MPI.COMM_WORLD.isend(hc_obj, rank, TAG.TAG_GET_HC.value)
        req.wait()
        #c_out("Command".center(50, '.'), Colors.OKBLUE)
        #c_out("-> Rank: {:d} has Received new Job!".format(rank), Colors.OKGREEN)
    except MPI.Exception as ex1:
        c_out("Exception in MPI "+str(ex1), Colors.FAIL)
    except Exception as e2:
        c_out("Thread task_send_hc task, "+str(e2), Colors.FAIL)


def job_master(jobs, hashhes):

    try:
        uid = 0
        tasks = []
        for hash_file in hashhes:
            for i in range(0, len(jobs)):
                for job in jobs[i]:
                    job.job_id = uid
                    job.hash_files = [hash_file, ]
                    tasks.append(Thread(target=task_send_newcmd, args=(job.make_seriable_object(), i, )))
            for t in tasks:
                t.start()
            for t in tasks:
                t.join()
            tasks.clear()
            uid += 1

    except Exception as e:
        c_out("Exception in job_master, " + str(e), Colors.FAIL)


def show_cmds():
    cmd_list = [("Status", "-s"), ("Command", "-c"), ("Info", "-i"), ("Exit", "-q"),
                ("Clear Screen", "cls")]
    c_out('=Command list='.center(30, '.'), Colors.BOLD + Colors.BOLD + Colors.HEADER)

    for item in cmd_list:
        c_out(item[0].ljust(25)+": "+Colors.OKGREEN+Colors.BOLD+item[1], Colors.WARNING)

    c_out('ex: !s 0 1 4      #for show node: 0 1 4 status', Colors.OKGREEN)

def timeout_checker(job, command, rank):
    job.join(4.0)
    if job.is_alive():
        c_out("Command-> {:s} Timeout!! on Rank: {:d}".format(command, rank), Colors.FAIL)
    else:
        del job





