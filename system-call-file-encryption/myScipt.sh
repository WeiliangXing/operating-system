#!/bin/bash
make
echo "Finished make"
sh install_module.sh
echo "Finished install kernel module"
dmesg | tail
echo "=================="
#test 1: normal encyption/decryption
./xcipher -p "this is password that is also a good password" -e "test2.txt" "test3.txt"
./xcipher -p "this is password that is also a good password" -d "test3.txt" "test4.txt"

echo "=================="
dmesg | tail
