# MPI-based-Hashcat

MPI Based Hashcat for distributing hashcat tasks to multiple computers.


# Installation

-> Install MPI with Multiple Thread Support


-> Install 'pexpect' module

    pip3 install pexpect
    
    https://pexpect.readthedocs.io/en/stable/install.html
    
-> Install mpi4py module

    pip3 install mpi4py
   
    https://mpi4py.readthedocs.io/en/stable/install.html
   
-> Download Hashcat binary for linux from https://hashcat.net/hashcat/

-> Edit Config File  'MPI-based-Hashcat/config.ini'

-> run __main__.py with mpirun ex: mpirun -np 6 python3 ./__main__.py

-> specify files and hashes

-> Do not pass '-l, -s, --quiet --status --remove --machine-readable --restore-disable --potfile-disable --session and -o' to external commands.

-> manual will be realesed soon

# Note 

-> this is beta version, please report issues
