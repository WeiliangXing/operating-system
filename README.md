# operating-system
projects about operating system

1 asyn-system:
	* Built an asynchronize system using producer-consumer model;
	* It can process several different I/O heavy tasks:
	  * files concatenation;
	  * file checksum;
	  * file compression;
	  * file encryption/decryption;

2 system-call-file-encryption:
	* Built a system call for file encryption/decryption;
	* Using AES ciphers in CBC mode;

3 wrap-vfs-firewall:
	* Implemented firewall functions in wrapped vfs which will be mounted to vfs;
	* The firewall function contains malicious signature database; Any file operations in vfs will be processed and filtered by the firewall before it goes into lower file system;
	* Added IOCTL for firewall control;
