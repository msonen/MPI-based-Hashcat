# MPI-based-Hashcat

MPI Based Hashcat for distributing hashcat tasks to multiple computers.


# Installation
-> Install MPI with Multiple Thread Support
-> Install 'pexpect' module
    pip3 install pexpect
    https://pexpect.readthedocs.io/en/stable/install.html
    
-> Install mpi4py module
   pip3 install mpi4pn
   https://mpi4py.readthedocs.io/en/stable/install.html
   
-> Download Hashcat binary for linux from https://hashcat.net/hashcat/

-> Edit Config File
-> run __main__.py with mpirun ex: mpirun -np 6 python3 ./__main__.py
-> specify files and hashes
-> Do not give '-l, -s, --quiet --status --remove --machine-readable --restore-disable --potfile-disable --session and -o' on external commands

