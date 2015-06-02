Hypershell
==========

Hypershell is a practical hypervisor layer guest OS shell that has all of the functionality of a traditional shell, but offers better automation, uniformity and centralized management.

Enviroment
==========
1.Host: Ubuntu 12.04

2.Guest: Debian 6 


Build
=====
1. build the kvm-kmod

    $ cd kvm-kmod  
    $ ./configure & make  

2. build qemu
   
    ```
    $ cd sse-qemu  
    $ mkdir build  
    $ cd build  
    $ ../configure --prefix=`pwd` --target-list=i386-softmmu --disable-werror --disable-strip  --enable-kvm  
    $ make install  
    ```

3. build syscall interception module
   
    $ cd sse  
    $ make  
 

RUN
===
1. load the new kvm-kmod

   cd kvm-kmod & ./load.sh  

2. start the VM

   ./qemu-i386-system guest.img --enable-kvm -monitor stdio

   In qemu terminal run start-sse

3. run the introspection program

   $ cd run  
   $ ./run.sh ps  





