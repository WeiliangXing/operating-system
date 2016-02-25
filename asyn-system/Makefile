# Please understand that I named kernel module so that it does not match the
# source file name
# * make submitjob - to build the kernel module
# * make demo - to build the user level program

obj-m += submitjob.o
submitjob-objs = sys_submitjob.o thread.o utils.o strops.o concat.o compress.o checksum.o encrypt.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: submitjob demo

demo: demo.c
	gcc -Wall -Werror -lssl -lpthread -lrt -I$(INC)/generated/uapi -I$(INC)/uapi demo.c -o demo

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f demo
