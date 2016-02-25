AMFS_VERSION="0.1"

EXTRA_CFLAGS += -DAMFS_VERSION=\"$(AMFS_VERSION)\"

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

#obj-$(CONFIG_AM_FS) += amfs.o
obj-m := amfs.o
amfs-objs := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall -Werror amfsctl.c -o amfsctl

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

#amfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o
