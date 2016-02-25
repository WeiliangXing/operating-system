CSE-506 (Fall 2015) Homework Assignment #2
Weiliang Xing
ID: 108211104

* Password for db operations:
12345678

* Purpose:
using "wrapfs" stackable file system techniques for anti-malware purposes

* Files: 
All functional codes are included in <Your kernel>/fs/amfs/

- amfs.h: header file for whole amfs file system. new added codes including
data structures for patterns, and all relative operation methods. Details see section Mechanisms;
- amfs_ioctl.h: header file for ioctl of patterns. Define methods including add, remove, list, size, 
password, etc. Details see section Mechanisms;
- amfsctl.c: user-ground .c file for pattern file operations including add, remove, list. Details see section Mechanisms;
- dentry.c: .c file for amfs operation. Not modified;
- file.c: .c file for amfs operation. modified methods for ioctl_ops, amfs_read, amfs_write, amfs_open, etc.
Modified codes mainly focusing on ioctl;
- inode.c: .c file for amfs operation. Not modified;
- Kconfig: configure file for amfs. Not modified;
- kernel.config: configuration file for kernel. *PLEASE DONT USE KERNEL in hw1!*
- lookup.c: .c file for amfs operation. Not modified;
- main.c: all detailed pattern file operations are implemented here. Also mount function are implemented here. Details see section Mechanisms;
- Makefile: makefile for module loading and make .c file;
- mmap.c: .c file for amfs operation. Not modified;
- myScript.sh: script file for whole needed scripting operations;
- myPatterns.db: original db file for patterns. NOT ENCRYPTED.
- README.md: readme file
- super.c: .c file for amfs operation. Add AMFS_SUPER_MAGIC number;
- test_*.txt: test files including "good" contents and "bad" contents;

* Operations:
> Mount: 
way1: $chmod 777 myScript.sh THEN $./myScript.sh
way2: $make THEN $insmod amfs.ko THEN $mount -t amfs -o pattdb=mypatterns.db  <Your directory> /mnt/amfs/
> pattern file operation:
NOTE:
Every operation below needs password to get access. The password is 12345678
invalid arguments include lack arguement, wrong arguments, etc.
1. To list known patterns
$ ./amfsctl -l /mnt/amfs

2. To add a new pattern
$ ./amfsctl -a "newpatt" /mnt/amfs

3. To remove an old pattern
$ ./amfsctl -r "oldpatt" /mnt/amfs
> bad/good files detection:
NOTE: all detections only works under mount point, as wrapfs indicates;
all operations including cat, vim, etc operations to open, write, read will be denied if teh file
is detected as "bad" file. For example:
$cat test_good1.txt will mark this file as good in EA, and gain access to it for next time immediately;
$cat test_bad1.txt will mark this file as bad in EA, and deny access to it for all future operations immediately.

* Mechanisms:
> Data Structure for patterns:
basic data structure will be a string array in amfs.h/struct patterns{} will live in amfs's super block private area. To make the array operations more efficient, I implemented several algorithms like heap sort, binary search, etc to make the time complexity of all operatons within O(mlogn) where m is length of max string and n is size of the array. Maximum capacity of the data structure would be 10 * PAGES, and maximum size of the array would be 100 as default. 
> Mounting:
mount will go through main.c/amfs_mount, which will begin reading myPatterns.db into superblock, followed by amfs_read_super to build superblock's pattern data structure. At this point, the patterns structure will always maintain sorted with high efficiency; also myPatterns.db will be always encrypted after mounting.
> ioctl:
ioctl is passed from user-ground .c file amfsctl.c to corresponding ioctl in amfs/amfs_unlocked_ioctl for more operations. There are four designed ioctls:
IOCTL_ADD: will add new pattern to myPatterns.db and the super-block data structure. Any illegal operations
like add patterns that already exist, or internal errors occurs will terminal adding;
IOCTL_REMOVE: will remove old pattern to myPatterns.db and the super-block data structure. Any illegal operations like add patterns that don't exist, or internal errors occurs will terminal removing;
IOCTL_LIST: will list all contents in super-block data structure;
IOCTL_SIZE: will return size of super-block data structure to user-ground
IOCTL_PASSWD: will compare password passed from user-ground with super-blcok data structure to determine whether the user has access to patterns file operations.
> File operations:
To detect good/bad file, under the mount point, try open/read/write file operations. This will trigger amfs_open/amfs_read/amfs_write method in file.c. For any file that is first access, before fs read it, my implementation will first scan contents in that file. Using strstr() method which is a exact string match, any file that contains any patterns in super block data structure will terminate future operations and return error. At the same time, the file's EA will be marked good or bad. Next time if user access the same file again, the file will not be scanned, but directly check EA to determine good or bad. 
> Encyption/Decryption:
To gain security to the patterns database, several methods are implemented to maintain encrypted status for the database file. The Encyption/Decryption will use ADS in CBC mode, with password used for user identification and encryption/decryption with hashed method(sha1).
The procedure is below:
At the first time of mounting, load plain myPatterns.db into amfs, and the .db will be encrypted immediately;
In future operations(add, remove patterns), the password is needed and used for encryption/decryption. The .db file will first be decrypted, then proceed the operation, then encrypted again. During whole procedure, the true content of .db file will never be exposed to outside.
Note that my method will generate a temp.db file during whole encryption and decryption. But in any condition the temp.db will not contain original content, which is safe for .db file all the time.

* Extra points:
1. I designed an efficient data structures with all operations in O(nlgm) time complexity;
2. I designed whole encryption/decryption system to protect the .db file, and thus the database will never exposed to anyone its true content except who has the password.

* References:
- code in homework 1
- A Stackable File System Interface for Linux
- Documentation/
- Linux/lib/sort.c

