#!/bin/bash
if grep -qs '/mnt/amfs' /proc/mounts; then
	umount /mnt/amfs
	echo "unmounted"
fi
if lsmod | grep "amfs"; then
	rmmod amfs
	echo "removed"
fi
make
echo "Finished make"
insmod amfs.ko
echo "Finished module loading"
echo "=================="
# mount -t amfs /usr/src/hw2-wxing/ /mnt/amfs/
# mount -t amfs -o /usr/src/hw2-wxing/ /mnt/amfs/
# mount -t amfs -o pattdb=   /usr/src/hw2-wxing/ /mnt/amfs/
# mount -t amfs -o pattdb=/usr/src/hw2-wxing/fs/amfs/mypatterns.db  /usr/src/hw2-wxing/ /mnt/amfs/
mount -t amfs -o pattdb=mypatterns.db  /usr/src/hw2-wxing/ /mnt/amfs/

# mount -t amfs -o pattdb=/mypatterns.db  /usr/src/hw2-wxing/ /mnt/amfs/
echo "Finished mount for hw2-wxing"

# ./amfsctl -l /mnt/amfs
# ./amfsctl -r "bye" /mnt/amfs
# ./amfsctl -r /mnt/amfs
# ./amfsctl
# echo "=================="

# cd /mnt/amfs/fs/amfs/
# cat test_good.txt
# cat test_bad.txt
# echo "first" >> test_good.txt
# echo "fi" >> test_good.txt

echo "=================="
dmesg | tail
echo "=================="
