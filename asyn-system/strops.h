#ifndef STROPS_H
#define STROPS_H

#include <linux/kernel.h>

/*PAGE volumn*/
#define PAGE 4096
#define BLOCK 16

int strops_files(void *arg); /* function to do strops_file operations */

int get_checksum(void *arg);
int isInputValid(void *arg);
int isInFileValid(struct file *readFilePtr);
int isOutFileValid(struct file *writeFilePtr);
int search_pat(void *arg);
int write_pat(void *arg, int mode);

#endif
