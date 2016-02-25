1) Brief Introduction
HW1 is done individually by Weiliang Xing (ID: 108211104).
HW1 is coded for designed a system call to encrypt/decrypt files.

2) Files
Main Code Files included:
> xcipher.c : user side function to accept arguments with password, inputfile, output file, encyption mode, etc. It will do system call for encyption/decryption

> sys_xcrypt.c : kernel side function to realize encryption/decrption system call. It accept myargs strcut as arguments.

> myargs.h  : a data structure that contains all input arguments for system call processing. 

> Makefile : a makefile for compiling purpose.

> myScript.h: A test script for testing purpose.

> install_module.sh: for module building

> kernel.config: config files for kernel configuration.

Testing files:
> test2.txt: input original file
> test3.txt: encrypted file
> test4.txt: decrypted file which completely equals to test2.txt if system call works.

3) Encyption/Decryption mechanism:
Here the system call use AES in CBC mode for encyption/decrption in function cryption() in file sys_xcrypt.c. 
User Side: we use MD5 build-in function to get hashed key and passed to syscall.
Kernel Side:
For encryption, the syscall will have below process to write to input file:
Step1: check validility of all inputs
Step2: check validility of writting and reading
Step3: Write hashed key as header into the first block in output file.
step4: Because all encryption/decryption are required as BLOCK = 16 in my style, so first calulate the how many chars left that cannot be moduled by 16.
Then extract first chars, and calculate padding length. Finally build a block combining padding indicater and first chars of original files, pass to encryption and write it to the output file.
Example: Suppose original file, the length % 16 = 3. Then extract first 3 chars of original file, say "nic". Then the padding length is 16 - 3 = 13, and transfer this number to padding indicater (13 -> 'c'), then build below block:
														ccccccccccccnic
with 13 'c's and 'nic'. This block has exactly 16 chars.
After this step, the original file are ensured to be fully moduled by 16.
Step5: Read file as PAGES(= 4096), and passed to encryption and write the results to output.
if final part of the original file is less than PAGE, then use the actual length of rest part for encyption and write to output.
Step6: clean and close file

For decryption, the syscall will have below process to write to input file:
Step1: check validility of all inputs
Step2: check validility of writting and reading
Step3: Read first block of encrypted file, compare with hashed key for whether two passwords matches.
Step4: Read second block of encrypted file, do decryption to get original context. Then read the first char of the block, translate this padding indicator to padding length, then determine which part is original content. Finally write it to decrypted file. For example: give decrypted block:
ccccccccccccnic, extract first char 'c', translate it and get the padding length 13, then start writting at index 13 which is "nic" to decrypted file.
Step5:  Read file as PAGES(= 4096), and passed to decryption and write the results to decrpted file.
if final part of the encrypted file is less than PAGE, then use the actual length of rest part for decyption and write to output.
Step6: clean and close file

4) Hash Mechanism:
There are two level hashing: one level in user side, and another in kernel side.
At user side I use MD5 in openssl/md5.h. This method created 32 unsigned char array; in this design, I trim first 16 bits as char array and send it into system call;
At kernel side I use SHA1 in linux/crypto.h. This method hashes the passed MD5 hashed key and hash it again to create a new array with size 16.
The final hashed key will add as the first block in encrypted file. For decryption, the first block will be extracted and compare the passed key to determine whether the user has access to the file.

5) Validition checking:
There are two level checking: one level in user side, and another in kernel side.
At user side we should check whether:
there is unknown option;
there is no input arguments at all;
there is no arguments while options are set;
there is no password while -p is set;
there is no setting while -d and -e are not set;
there is setting for -d and -e at the same time;
the length of setting in -p is less than 6;
there is no arguments while -d or -e is set.

At kernel side we should check whether:
any attribute in struct myargs is null;
length of key and key's length does not match;
the cryption mode is not recognizable;
shallow check:the input and output file points to same file;
the file path is too long;
there is error to allocate the passed structure myargs;
there is error to copy struct myargs into kernel;
there is error to read input file;
there is no read permission for input file;
the input file is empty;
the input file is not regular;
there is error to read output file;
there is no write permission for output file;
the output file is not regular;
deep check: the input and output file points to same file;
Any mallocation has error during encyption or decryption.
For Decyption, also check whether:
hashed key is legal;
hashed key is matched to decrypted key;
the padding is not valid;


6) References:
sys_xcypt.c:
The cryption core methods are referened from linux/net/ceph/crypto.c function: ceph_aes_encrypt() and cepth_ase_decrpyt()
xcipher.c:
The use of getopt() is referred from example in gnu.org
http://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
kernel.config
Part of the configuration process are in discussion with AoJie.
The use of MD5 referenced from 
Documentation/crypto/api-intro.txt
crypto/tcrypt.c
7) Note:
warning: sys_xcrypt.c:488: warning: ISO C90 forbids mixed declarations and code 
Explanation: for C90 standard, array cannot mix declaration adn assigment. For this line, however, we have to design in this style to avoid error.






