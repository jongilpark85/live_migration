# Process Live Migration
1. Overview

    Live migration is moving a running process to another host, and there are two approaches widely used, Pre-Copy and Post-Copy.
    This project implements a simple Post-Copy live migration by using userfaultfd.
    userfaultfd allows the user application to handle page faults in user space.
    The original/target process prints a number at time intervals in increasing order.
    libsender.so is a shared library that is loaded to the orginal/target process.
    A SIGUSR2 signal invokes libsender.so to start migration.
    Once live migration starts, the original/target process stops its execution to prevent its content from being changed.
    The sender( original process + libsender.so) sends /maps/self/maps file and context information of the orginal process to the receiver.
    Then, the receiver performs a context switch in the main thread to run as the original process.
    Even after the context switch, the migration handling thread keeps running to handle page faults.
    Since the receiver does not have any page of the original process yet, it gets a page fault.
    On a page fault, the main thread stops its execution, and the migration trhead sends a page request to the sender.
    The sender sends the content of the requested page to the receiver.
    Then, the migration thread copies the content to the faulting region, and the main thread resumes its execution.
    This is repeated until the receiver has all the pages the original process uses.


2. Future work

    The current implementation is minimal and has limited functionality.
    To be a complete solution, a live migration should support multi-threads, open file descriptors, network connections, etc.
    In addition, Post-Copy migration works based on page fault handling, so it is important to minimize page faults.
    Using a combination of Pre-Copy and Post-Copy would be an optimal solution for process live migration.


3. System Requirements

    Linux (64 bit)

    Kernel Version 4.3 or higher (for userfualtfd)


4. Complie

    You can use one of the following commands on a terminal

    $ make

    $ make build

    $ make rebuild


5. Remove object files and executables

    $ make clean


6. Automated Test
    1) Run the test program on a terminal

        You can use one of the following commands on a terminal

        $ make test

        $ python test.py

        To make sure that the receiver keeps running without any problem, the test program does not terminate the receiver 

    2) Kill the receiver

        $ pidof receiver

        $ kill -9 [PID of receiver]

        If "pidof receiver" does not show any ID, then, press ctrl + c on the terminal where the receiver is running
        

7. Manual Test (After compilation)
    1) Run the recceiver on a terminal

        $ ./receiver

    2) Run the target process on another terminal

        $ LD_PRELOAD=./libsender.so ./target

    3) Check the output from the target process on the second terminal

        The target process prints a number at time intervals in increasing order

    4) Send a SIGUSR2 signal to the target process

        $ pidof target

        $ kill -12 [PID of target]

        Now, the target process stops and does not print any number
    
    4) Check the output from the receiver on the first terminal
    
        The receiver starts priting a number from where the target process got paused

    5) Kill the receiver

        $ pidof receiver

        $ kill -9 [PID of receiver]

        If "pidof receiver" does not show any ID, then press ctrl + c on the first terminal


8. Usage (If no argument is given, pre-defined default values are used)
    1) Receiver

        $ ./receiver [port]

        port is the port number on which the receiver is listening to accept a connection from the sender

    2) Original/Target process and libsender.so

        $ LD_PRELOAD=./libsender.so ./target

        libsender.so is a shared library, so it does not take command-line arguments.

        Instead, libsender.so gets the IP and port of the receiver from receiver_info.txt 
        
        If receiver_info.txt does not exist, pre-defined default values are used
