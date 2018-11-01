from copy import copy
from sys import exit, stderr
from os import system
from pyCat import args
from pyCat.tasks_master import *
from pyCat.utils import c_out, Colors, calculate_workload
from threading import Thread
from pyCat.client import Client
import pyCat.hashcat as hc
try:
    from mpi4py import MPI
except Exception as e:
    print("'mpi4py' package not found ", str(e))
    exit(-1)


def organize_jobs(size, rank):

    bench_scores = []
    MPI.COMM_WORLD.Barrier()
    avaliable_job_list = {}     # {rank: [hashcat1, hashcat2, ....]}
    c_out("-> Retrieving Benchmark Scores ..", Colors.WARNING)
    bench_scores.append((args.Config.benchmark_score, MPI.COMM_WORLD.Get_rank()))
    for i in range(0, size):
        avaliable_job_list[i] = []
        if i == rank:
            continue
        score = MPI.COMM_WORLD.recv(tag=TAG.TAG_BENCHMARK.value, source=i)
        bench_scores.append((score, i))  # append score and rank
    for score in bench_scores:
        c_out("Rank {:d}  Score {:d}".format(score[1], score[0]), Colors.OKBLUE)
    hashcats, attack_mode, hashes = args.get_arguments()
    if hashcats is None:
        c_out("Bad Arguments", Colors.BOLD+Colors.FAIL)
        MPI.Comm.Abort(MPI.COMM_WORLD, -1)
        exit(-1)
    c_out("-> Checking Arguments .....", Colors.WARNING)
    chc_result, respond = hashcats[0].test_argumants()
    if not chc_result:
        print("Arguments Test Failed Check Your arguments", file=stderr)
        c_out("Command-> " + Colors.WARNING + hashcats[0].build_command(), Colors.FAIL)
        if respond:
            c_out("Error: " + respond+"\n", Colors.FAIL)
        MPI.Comm.Abort(MPI.COMM_WORLD, -1)
        exit(-1)

    if attack_mode in (3, 6, 7):
        c_out("-> {:d} mask(s) found! ".format(len(hashcats)), Colors.BOLD+Colors.OKGREEN)
        ic = 0
        for cat in hashcats:
            keyspace = cat.calculate_keyspace()
            if keyspace:
                c_out("Job -> {:d} Base Loop Count (Keyspace): {:d}".format(ic, keyspace), Colors.OKGREEN)
                workloads = calculate_workload(bench_scores, keyspace)
                for i in workloads.keys():
                    temp = copy(cat)
                    temp.skip = workloads[i][0]
                    temp.limit = workloads[i][1]
                    avaliable_job_list[i].append(temp)
            else:
                c_out("Keyspace Calculation failed", Colors.FAIL)
                MPI.Comm.Abort(MPI.COMM_WORLD, -1)
                exit(-1)
            ic += 1
    elif attack_mode == 0 or attack_mode == 1:
        cat = hashcats[0]
        keyspace = cat.calculate_keyspace()
        if keyspace:
            c_out("Base Loop Count (Keyspace): {:d}".format(keyspace), Colors.OKGREEN)
        else:
            c_out("Keyspace Calculation failed", Colors.FAIL)
            MPI.Comm.Abort(MPI.COMM_WORLD, -1)
            exit(-1)
        workloads = calculate_workload(bench_scores, keyspace)
        for i_rank in workloads.keys():
            temp = copy(cat)
            temp.skip = workloads[i_rank][0]
            temp.limit = workloads[i_rank][1]
            avaliable_job_list[i_rank].append(temp)

    else:
        pass
    return avaliable_job_list, hashes


def task_console():

    ptrcmd = True
    flag = True
    global task, target
    size = MPI.COMM_WORLD.Get_size()
    loop = False
    while flag:
        if ptrcmd:
            show_cmds()
            ptrcmd = False
        inp = input(Colors.BOLD + Colors.OKGREEN + 'input: ')
        chunks = inp.split()
        rank_id = range(0, size)
        if len(chunks) > 1:
            ids = chunks[1:]
            ids_int = []
            for i in ids:
                try:
                    p = int(i)
                    if p not in range(0, size):
                        c_out("Value {:d} must be between [0-{:d}]".format(int(i), size-1), Colors.FAIL)
                        loop = True
                        break
                    ids_int.append(p)
                except ValueError:
                    c_out("Rank id must be integer!!", Colors.FAIL)
                    loop = True
                    break
            if loop:
                loop = False
                continue
            rank_id = ids_int
            del ids

        dup = chunks[0]
        cmd = None
        if dup == 's':
            target = task_ask_status
        elif dup == 'c':
            cmd = input(Colors.BOLD + 'Command -> ')
            target = task_command
        elif dup == 'q':
            MPI.Comm.Abort(MPI.COMM_WORLD, 0)
            exit(0)
        elif dup == 'i':
            target = task_ask_info
        elif dup == "cls":
            system('clear')
        else:
            c_out('-> Unrecognized Command', Colors.BOLD+Colors.FAIL)
            ptrcmd = True
            continue
        copy_data = copy(rank_id)
        del rank_id
        if not ptrcmd and target:
            tasks = []
            for r in copy_data:
                if cmd is not None:
                    task = Thread(target=target, args=(cmd, r, ))
                else:
                    task = Thread(target=target, args=(r, ))
                task.setDaemon(True)
                task.start()
                tasks.append(task)
                Thread(target=timeout_checker, args=(task, dup, r)).start()
            for t in tasks:
                t.join()

