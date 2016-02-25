#ifndef A3_ENCRYPT_H
#define A3_ENCRYPT_H

#define ENCRYPT 1
#define DECRYPT 2

#define AES 3
#define BLOWFISH 4

struct kjob_info;

int hw3_encrypt(struct kjob_info* job);
int hw3_encrypt_wrapper(struct kjob_info* job);

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#endif
