import threading
from enum import Enum
from time import sleep
import signal
import re

try:
    import pexpect
except ModuleNotFoundError:
    print("Module 'pexpect' not found")
    exit(-1)


class STATUS(Enum):

    Initializing = 0
    Autotuning = 1
    Selftest = 2
    Running = 3
    Paused = 4
    Exhausted = 5
    Cracked = 6
    Aborted = 7
    Quit = 8
    Bypass = 9
    Error = 13


class HC_STATE:

        def __init__(self):
            self.status = STATUS.Initializing
            self.speed = []
            self.Exec_Runtime = 0
            self.CURKU = 0
            self.progress = (0, 1)
            self.rechash = (0, 0)
            self.recsalt = (0, 0)
            self.temp = []
            self.rejected = 0
            self.limit = 0
            self.skip = 0
            self.job_id = -1
            self.util = []
        def get_progress(self):
            return (float(self.progress[0])/float(self.progress[1]))*100.0

        def get_speed(self):
            s_list = []
            for sp in self.speed:
                s_list.append((float(sp[0])/float(sp[1]))*100.0)
            return s_list

        def __str__(self):
            string = 'Status'.ljust(18) + ":" + str(self.status)
            string += '\nSpeed'.ljust(18) + ": " + str(self.get_speed())
            string += '\nExecTime'.ljust(18) + ": "+str(self.Exec_Runtime)
            string += '\nRestore Point'.ljust(18) + ": "+str(self.CURKU)
            string += '\nProgress'.ljust(18) + ": " + "{:d}/{:d}  {:.3f}%".format(self.progress[0], self.progress[1],
                                                                                  self.get_progress())
            string += '\nRecovered Hash'.ljust(18) + ": " + (str(self.rechash[0]) + '/' + str(self.rechash[1]))
            string += '\nRecovered Salt'.ljust(18) + ": " + (str(self.recsalt[0]) + '/' + str(self.recsalt[1]))
            string += '\nRejected'.ljust(18) + ": " + str(self.rejected)
            string += '\nTemp'.ljust(18) + ": " + ' '.join(self.temp)
            string += '\nUtil'.ljust(18) + ": " + ' '.join(self.util)
            string += '\nJob ID'.ljust(18) + ": " + str(self.job_id)
            string += '\nSkip'.ljust(18) + ": " + str(self.skip)
            string += '\nLimit'.ljust(18) + ": " + str(self.limit)
            return string


class HC_EXIT_STATUS(Enum):

    CRACKED = 0
    EXHAUSTED = 1
    QUIT = 2
    ABORTED_CHECKPOINT = 3
    ABORTED_RUNTIME = 4
    ERROR = -1
    BAD_ARGUMETNS = 255
    GPU_WATCHDOG = 254
    NON_EXIT = None


class Hashcat(threading.Thread):

    search_pattern = r"STATUS[\s\dA-Z_.]*\d+" # Machine Readable çıktısını yakalamak için kullanılan regex
    reserved_keywords = ('STATUS', 'SPEED', 'EXEC_RUNTIME', 'CURKU', 'PROGRESS', 'RECHASH', 'RECSALT', 'TEMP',
                         'REJECTED', 'UTIL')

    def __init__(self, exec_path: str ="./hashcat/hashcat64.bin", hash_mode: int = 0, attack_mode: int = 0,
                 status_update_interval: int=100, outfile="./outfile.txt", spec_command=None, session='mysession',
                 outfile_chk_dir= None, job_id=-1):
        threading.Thread.__init__(self)
        self.hash_mode = hash_mode   # hash type
        self.attack_mode = attack_mode    # Atak type
        self.exec = exec_path   # Dşrectory for hashcat
        self.increment = False  # is increment mode
        self.pwMin = 1  # min password length
        self.pwMax = 64  # max password length
        self.skip = 0  # skip passwords from that point
        self.limit = 0  # maximum attempt (basecount for)
        self.external_commands = ['--quiet',  "--status", "--machine-readable", "--restore-disable",
                                  "--potfile-disable"]
        self.dict_files = []  # Wordlist files
        self.hash_files = []  # Hash files
        self.rule_files = []  # rule files
        self.isRuleBased = False  # is rulebased attack?
        self.process = None  # Hashcat child process
        self.hc_state = HC_STATE()  # state object
        self.mutex = threading.Lock()  # mutex
        self.isover = False
        self.invoke_after_termination = None  # callback function after termination
        self.regex = re.compile(Hashcat.search_pattern, re.M)  # regex for capture hashcat state
        self.mask = ''  # mask pattern
        self.outfile_path = outfile  # passwords to write
        self.spec_command = spec_command
        self.session = session  # Hashcat process name
        self.outfile_check_dir = outfile_chk_dir  #
        self.job_id = job_id  # job id (it must be same for divided job)

    def build_command(self):
        cmd_args = []
        cmd_args.append('-a '+str(self.attack_mode))
        cmd_args.append('-m ' + str(self.hash_mode))
        cmd_args.append(' '.join(self.hash_files))
        if self.attack_mode == 0:
            for file in self.dict_files:
                cmd_args.append(file)

            if self.isRuleBased:
                for rule in self.rule_files:
                    cmd_args.append('-r')
                    cmd_args.append(rule)

        elif self.attack_mode == 1:
            for file in self.dict_files:
                cmd_args.append(file)

        elif self.attack_mode == 3:
            cmd_args.append(self.mask)
        elif self.attack_mode == 6:
            for file in self.dict_files:
                cmd_args.append(file)
            cmd_args.append(self.mask)
        elif self.attack_mode == 7:
            cmd_args.append(self.mask)
            for file in self.dict_files:
                cmd_args.append(file)
        cmd_args.extend(self.external_commands)
        cmd_args.append('--session='+self.session)
        cmd_args.append('-o '+self.outfile_path)
        if self.outfile_check_dir:
            cmd_args.append('--outfile-check-dir='+self.outfile_check_dir)
        if self.attack_mode in (0, 1, 3):
            cmd_args.append("-s " + str(self.skip))
            if self.limit > 0:
                cmd_args.append("-l " + str(self.limit))
        return ' '.join(cmd_args)

    def get_hc_state(self):
        if self.process:
            self.mutex.acquire()
            p = self.process
            try:
                p.send('s')
                buffer = p.read_nonblocking(256, 100)
                snc = self.regex.search(buffer)
                if snc:
                    dump = snc.group()
                    lst_var = list(filter(None, dump.split('\t')))
                    st = HC_STATE()
                    i = 0
                    flag = True
                    while i < len(lst_var) and flag:
                        if lst_var[i] == 'STATUS':
                            st.status = STATUS(int(lst_var[i + 1]))
                            i += 2
                            continue
                        if lst_var[i] == 'SPEED':
                            j = i + 1
                            while lst_var[j] not in Hashcat.reserved_keywords:
                                st.speed.append((int(lst_var[j]), int(lst_var[j + 1])))
                                j = j + 2
                            i = j
                            continue
                        if lst_var[i] == 'TEMP':
                            j = i + 1
                            while lst_var[j] not in Hashcat.reserved_keywords:
                                st.temp.append(lst_var[j])
                                j = j + 1
                            i = j
                            continue
                        if lst_var[i] == 'EXEC_RUNTIME':
                            st.Exec_Runtime = float(lst_var[i + 1])
                            i += 2
                            continue
                        if lst_var[i] == 'CURKU':
                            st.CURKU = int(lst_var[i + 1])
                            i += 2
                            continue
                        if lst_var[i] == 'PROGRESS':
                            st.progress = (int(lst_var[i + 1]), int(lst_var[i + 2]))
                            i += 3
                            continue
                        if lst_var[i] == 'RECHASH':
                            st.rechash = (int(lst_var[i + 1]), int(lst_var[i + 2]))
                            i += 3
                            continue
                        if lst_var[i] == 'RECSALT':
                            st.recsalt = (int(lst_var[i + 1]), int(lst_var[i + 2]))
                            i += 3
                            continue
                        if lst_var[i] == 'REJECTED':
                            st.rejected = int(lst_var[i + 1])
                            i += 2
                            continue
                        if lst_var[i] == 'UTIL':
                            j = i + 1
                            while lst_var[j] not in Hashcat.reserved_keywords:
                                st.util.append(lst_var[j])
                                j = j + 1
                                if j >= len(lst_var):
                                    break
                            i = j
                            continue
                        break

                    st.limit = self.limit
                    st.skip = self.skip
                    st.job_id = self.job_id
                    self.hc_state = st
            except Exception as e:
                print('inner Run:', e)
            finally:
                self.mutex.release()

            return self.hc_state

    def run(self):
        strcmd = self.exec + " "
        if self.spec_command:
            strcmd += self.spec_command
        else:
            strcmd += self.build_command()
        #print("\n[SLAVE]", strcmd)
        p = pexpect.spawnu(strcmd)
        p.maxread = 1024
        self.process = p
        sleep(0.5) # wait if command error occured
        try:
            p.wait()
        except Exception as e:
            print(e)
        finally:
            if p.isalive():
                self.terminate()
                sleep(0.5)
                if p.isalive():
                    p.terminate(True)
            self.isover = True
            if self.invoke_after_termination:
                self.invoke_after_termination(self)
            #print("Exit Status", HC_EXIT_STATUS(p.exitstatus))

    def calculate_keyspace(self):
        command = " ".join([" -a", str(self.attack_mode), "-m", str(self.hash_mode)])
        if self.attack_mode == 3:
            command += " " + self.mask
        else:
            if self.attack_mode == 7:
                command += " " + self.mask
            command += " " + " ".join(self.dict_files)
            if self.attack_mode == 6:
                command += ' ' + self.mask
        command += " --keyspace --quiet"
        respond = pexpect.run(self.exec + command)
        try:
            v = int(respond)
            return v
        except ValueError as e:
            print("Keyspace failed! ", respond)
            print("Command-> ", command)
            return None

    def cmd(self, command: str):
        try:
            self.mutex.acquire()
            if command == 'q' or command == '-q':
                threading.Thread(target=Hashcat.get_hc_state, args=(self, )).start()

            self.process.send(command)
            sleep(0.1)
            string = self.process.read_nonblocking(256, 100)
            return string
        except pexpect.TIMEOUT:
            return 'Command Timed out, try again later'
        except pexpect.exceptions.EOF:
            return 'process may be terminated, Exit Code: ' + str(self.get_exit_status())
        except TimeoutError:
            return 'Time out Error Try again later'
        except Exception as e:
            return 'Unknown Error: ' + str(e)

        finally:
            self.mutex.release()

    def terminate(self, force_kill=False):
        if force_kill:
            self.process.kill(signal.SIGKILL)
        else:
            self.process.send('q')

    def get_exit_status(self):
        if self.process:
            return HC_EXIT_STATUS(self.process.exitstatus)
        return HC_EXIT_STATUS(None)

    def is_over(self):
        return self.isover

    def is_running(self):
        if self.process:
            return self.process.isalive()
        return False

    def __str__(self):
        string = "STATUS: " + str(self.hc_state.status) + "\n"
        string += "Command" + self.build_command()
        return string

    def make_seriable_object(self):

        obj = []
        obj.append(self.attack_mode)
        obj.append(self.hash_mode)
        obj.append(self.external_commands)
        obj.append(self.mask)
        obj.append(self.dict_files)
        obj.append(self.rule_files)
        obj.append(self.hash_files)
        obj.append(self.isRuleBased)
        obj.append(self.increment)
        obj.append(self.pwMax)
        obj.append(self.pwMin)
        obj.append(self.limit)
        obj.append(self.skip)
        obj.append(self.job_id)
        return obj

    @staticmethod
    def combine_from_object(obj: list, exec: str, outfile: str):
        h = Hashcat(exec_path=exec, outfile=outfile)
        h.attack_mode = obj[0]
        h.hash_mode = obj[1]
        h.external_commands = obj[2]
        h.mask = obj[3]
        h.dict_files = obj[4]
        h.rule_files = obj[5]
        h.hash_files = obj[6]
        h.isRuleBased = obj[7]
        h.increment = obj[8]
        h.pwMax = obj[9]
        h.pwMin = obj[10]
        h.limit = obj[11]
        h.skip = obj[12]
        h.job_id = obj[13]
        return h

    def test_argumants(self):

        try:
            strcmd = self.exec + " "
            if self.spec_command:
                strcmd += self.spec_command
            else:
                strcmd += self.build_command()
            # print("\n[SLAVE]", strcmd)
            p = pexpect.spawnu(strcmd)
            sleep(3.5)
            if p.isalive():
                p.kill(signal.SIGKILL)
                return True, None

            stat_obj = HC_EXIT_STATUS(p.exitstatus)
            if stat_obj == HC_EXIT_STATUS.ERROR or stat_obj == HC_EXIT_STATUS.BAD_ARGUMETNS:
                return False, p.read_nonblocking(256)

            return True, None
        except pexpect.exceptions.ExceptionPexpect:
            return False, None
        except Exception as e:
            print("Exception in test_argument function", e)
            return False, None

