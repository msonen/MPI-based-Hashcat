from sys import stderr
from os.path import isfile, exists
from os import makedirs
from pyCat.hashcat import Hashcat
from copy import copy
from configparser import ConfigParser
from pyCat.utils import Colors, c_out


class Config:

    exec_path = "hashcat64.bin"
    benchmark_score = 50
    outfile_path = "./outfile.txt"
    session_name = "session"
    outfile_chk_dir = ''
    outfile_enable = False
    outfile_timer = 5
    temp_path = ''

    @staticmethod
    def get_config():
        conf = ConfigParser()
        try:
            conf.read("./config.ini")
            Config.exec_path = conf.get('Hashcat', 'Hashcat_Exec_Path').split('#')[0].strip()
            Config.session_name = conf.get('Hashcat', 'Hashcat_Session').split('#')[0].strip()
            Config.benchmark_score = int(conf.get('Hashcat', 'Benchmark_Score').split('#')[0].strip())
            Config.outfile_path = conf.get('Outfile', 'Hashcat_Out_File').split('#')[0].strip()
            Config.outfile_chk_dir = conf.get('Outfile', 'Outfile_check_dir').split('#')[0].strip()
            Config.temp_path = conf.get('Hashcat', 'Hashcat_Temp_Path').split('#')[0].strip()
            snc = conf.get('Outfile', 'Outfile_check_enable').split('#')[0].strip()
            if snc == '1':
                Config.outfile_enable = True
            directory = '/'.join(Config.outfile_path.split('/')[:-1])
            if not exists(directory):
                makedirs(directory)
        except Exception as e:
            print("Configuration file corrupt", str(e))
            exit(-1)


def get_files(prompt):
    '''

    :param prompt:  message prompt for File lists
    :return: file path list
    '''
    flag = True
    global files
    while flag:
        dump = input(Colors.BOLD + prompt)
        files = dump.split()
        flag = False
        for file in files:
            if (not (isfile(file) or isfile('./' + file))) and not flag:
                print('File: ' + file + " is not correct file, check its path\n", file=stderr)
                flag = True
    return files


def get_int_param(prompt: str):
    '''
    get an integer value from user
    :param prompt: message
    :return:
    '''
    flag = True
    global mode
    while flag:
        try:
            mode = int(input(Colors.BOLD + prompt))
            flag = False
        except ValueError:
            c_out("Value must be integer!\n", Colors.WARNING)
    return mode


def open_mask_file(h: Hashcat, file_path):
    '''
    this function create object list from one object that include multiple mask value
    :param h: hashcat object
    :param file_path: for mask file
    :return:  hashcat object list
    '''
    ret = []
    with open(file_path, "r") as lines:
        for line in lines:
            if line.startswith("#"):
                continue
            h.mask = line[:-1]
            ret.append(h)
            h = copy(h)
    return ret


def get_arguments():
    '''
    get arguments from user
    :return: hashcat object list, attack_mode and hash files (if multiple hashes create a temporary files and directory)
    '''
    attack_mode = get_int_param(Colors.BOLD+Colors.WARNING + "Enter Attack Mode: ")
    hash_mode = get_int_param(Colors.BOLD+Colors.WARNING + "Enter Hash Type: ")
    global ruleFile
    hash_files = get_files("Enter Hash File(s): ")
    lines = []
    for page in hash_files:
        with open(page, "r") as f:
            for line in f:
                if line.strip():
                    lines.append(line)
    c_out("-> {:d} hash found!".format(len(lines)), Colors.OKBLUE)
    dir_out = None
    if Config.outfile_enable:
        dir_out = Config.outfile_chk_dir
    h = Hashcat(outfile=Config.outfile_path, exec_path=Config.exec_path, outfile_chk_dir=dir_out)
    h.attack_mode = attack_mode
    h.hash_mode = hash_mode
    h.hash_files = hash_files
    ret = []
    if attack_mode == 0:
        #print("Dictionary Attack Mode".center(40, "."))
        dict_files = get_files("Dictionary File(s): ")
        r = input(Colors.BOLD+Colors.WARNING+"Do You Want to add rule file? Y/N:")
        if r.upper() == "Y":
            ruleFile = get_files("Enter Rule File: ")
            h.isRuleBased = True
            h.rule_files = ruleFile
        h.dict_files = dict_files
        ret.append(h)
    elif attack_mode == 1:
        #print("Combinator Attack Mode".center(40, "."))
        dict_files = get_files(Colors.BOLD+Colors.OKGREEN+"Dictionary Files: ")
        h.dict_files = dict_files
        ret.append(h)
    elif attack_mode == 3:
        mask = input("Enter Mask or mask file: ")
        if isfile(mask):
            ret.extend(open_mask_file(h, mask))
        else:
            h.mask = mask
            ret.append(h)
    elif attack_mode in (6, 7):
        dict_files = get_files(Colors.BOLD + "Dictionary File: ")
        h.dict_files = dict_files
        mask = input("Enter Mask or mask file: ")
        if isfile(mask):
            ret.extend(open_mask_file(h, mask))
        else:
            h.mask = mask
            ret.append(h)
    else:
        c_out("Unspupported Attack Mode", Colors.FAIL)
        return None, attack_mode, None
    external_command_string = input(Colors.BOLD+Colors.WARNING+"Enter External Commands: ")
    external_commands = external_command_string.split()
    for rt in ret:
        for cmd in external_commands:
            if cmd not in rt.external_commands:
                rt.external_commands.append(cmd)

    job_id = 0
    hashes = []
    path = Config.temp_path
    if not exists(path):
        makedirs(path)
    for line in lines:
        file_path = path + 'job' + str(job_id) + '.hash'
        with open(file_path, "w") as f:
            f.writelines([line])
        hashes.append(file_path)
        job_id += 1
    return ret, attack_mode, hashes
