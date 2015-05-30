sudo rmmod kvm_intel
sudo rmmod kvm
lsmod | grep kvm
echo 'kvm-intel and kvm removed'
cd ~/kvm-kmod/x86/
sudo insmod kvm.ko
sudo insmod kvm-intel.ko
lsmod | grep kvm
