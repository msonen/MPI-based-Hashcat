from pyCat import *
from queue import Queue


def main():
    '''
    main function for organize jobs
    :return:
    '''
    rank = MPI.COMM_WORLD.Get_rank()
    size = MPI.COMM_WORLD.Get_size()
    if MPI.Query_thread() != MPI.THREAD_MULTIPLE:
        print("'Your MPI version does not support multiple threading', build MPI with '--enable-thread-multiple' flag")
        MPI.Comm.Abort(MPI.COMM_WORLD, -1)
        exit(-1)
    args.Config.get_config()
    if rank == 0:
        c_out(Colors.BOLD + "=> WELCOME TO DISTRIBUTED HASHCAT <=", Colors.OKGREEN)
        mytasks = (Thread(target=task_console, args=()), Thread(target=task_catch_error, args=()),
                   Thread(target=task_job_finished_receiver, args=()))
        jobs, hashes = organize_jobs(size, rank)
        q = Queue(maxsize=0)
        slave = Client(MPI.COMM_WORLD, q, benchmark_score=args.Config.benchmark_score,
                       outfile_chk_dir=args.Config.outfile_chk_dir)
        slave.setDaemon(True)
        slave.setName("job" + str(rank))
        slave.start()
        c_out("-> {:d} job(s) avaliable!!".format(len(hashes) * size), Colors.OKGREEN + Colors.BOLD)

        for t in mytasks:
            t.setDaemon(True)
            t.start()

        job_master(jobs, hashes)
        slave.join()
        print("END MASTER")
    else:
        q = Queue(maxsize=0)
        slave = Client(MPI.COMM_WORLD, q, benchmark_score=args.Config.benchmark_score,
                       outfile_chk_dir=args.Config.outfile_chk_dir)
        MPI.COMM_WORLD.Barrier()
        slave.send_benchmark_score()
        slave.setDaemon(True)
        slave.setName("job" + str(rank))
        slave.start()
        slave.join()


main()