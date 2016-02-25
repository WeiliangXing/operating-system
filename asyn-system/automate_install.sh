#!/bin/sh
# hmm, what does variable expansion mean?
# set -x

# Here are the steps the script executes
#  Removes module
#  Build module
#  Install module
#  Build user level program (but does not run, so run it your self or uncomment ./demo)
# fix signal.h
sed -e '/# include <bits\/sigcontext.h>/ s/^#*/\/\/#/' -i /usr/include/signal.h
MODULE_NAME=submitjob

if lsmod | grep "$MODULE_NAME" &> /dev/null ; then
    echo "Removing module"
    rmmod $MODULE_NAME
fi

if [ -f "$MODULE_NAME.ko" ] ; then
    rm -f "$MODULE_NAME.ko"
fi

make submitjob

if [ -e "$MODULE_NAME.ko" ]
then
    echo "Installing module:"
    insmod $MODULE_NAME.ko
    echo "After installing module"
    lsmod | grep $MODULE_NAME
    dmesg | tail -n 5
else
    echo "Module kernel object does not exist! Check your build.."
    exit
fi

USER_PROGRAM_NAME=demo
rm -f "$USER_PROGRAM_NAME"
make $USER_PROGRAM_NAME
if [ -e "$USER_PROGRAM_NAME" ]
then
    echo "Now you can run ./$USER_PROGRAM_NAME"
    # ./demo
    # echo "dmesg output, 25 lines\n===========================\n"
    # dmesg | tail -n 25
else
    echo "Binary $USER_PROGRAM_NAME does not exist! Check your build.."
    exit
fi

