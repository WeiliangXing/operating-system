#ifndef STRUTILS_H
#define STRUTILS_H
#include <linux/slab.h>  /* kmalloc */
#include <linux/uaccess.h>  /* copy_from_user */
#include "common.h"
/* string helpers */
int resolve_fullpath_from_user(char *dst, char __user *src, int flags, int mode);
int copy_user_str(char **mod_str, char __user *user_str);
void print_hexdump(char *hex);
/* I/O */
int write_file(struct file *filp, void *buf, int count);

/* Pipes (messaging) */
int init_messaging(void);
void free_messaging(void);

/* resolve_pipe gets a file structure by its descriptor.
 After using the file, call fput to decrement use count*/
struct file *resolve_pipe(int pipefd);
int send_err(struct file *pipe, int errcode, char *fmt, ...);
int send_info(struct file *pipe, char *msg);
int send_errc(struct file *pipe, int errcode);
void send_finish(struct file *pipe);
void terminate_msg(struct file *pipe);

int create_pipe(struct kjob_info* kjob, struct kjob_info* ujob);
#endif
