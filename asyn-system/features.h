#ifndef __FEATURES_H_
#define __FEATURES_H_

#include "common.h"

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* CHECKSUM */

/* copies from userland to kernelland*/
int copy_checksum_struct(struct kjob_info *kjob, struct kjob_info *ujob);

/* Copies checksum structure in kernel space. After that it frees src options
 but not the src itself (since it's a shared buffer used by producer_fn)*/
int kcopy_checksum_info(struct kjob_info *dst, struct kjob_info *src);
void free_checksum_opts(struct kjob_info *job);
/* checksum computation */
int get_checksum(void *jobinforaw);

/* CONCAT */
/* function to do concat_file operations*/
int concat_files(struct kjob_info* job);
int kcopy_concat_info(struct kjob_info *dst, struct kjob_info *src);

/* Copies the concat struct from userland to kernel
 * copy follows every pointer member (recursively)
 */
int copy_concat_struct(struct kjob_info *kjob, struct kjob_info *ujob);

void free_concat_opts(struct kjob_info *job);


/* COMPRESS */
int copy_compress_struct(struct kjob_info *kjob,  struct kjob_info *ujob);
/* Copies compress structure in kernel space. After that it frees src options
 but not the src itself (since it's a shared buffer used by producer_fn)*/
int kcopy_compress_info(struct kjob_info *dst, struct kjob_info *src);
int hw3_compress(struct kjob_info *kjob);
void free_compress_opts(struct kjob_info *job);

/* ENCRYPT */

int hw3_encrypt(struct kjob_info* job);
int kcopy_encrypt_info(struct kjob_info *dst, struct kjob_info *src);
int copy_encrypt_struct(struct kjob_info *kjob, struct kjob_info  *ujob);
void free_encrypt_ops(struct kjob_info *job);

#endif
