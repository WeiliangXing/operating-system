#ifndef DEMO_U_H
#define DEMO_U_H
#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <fcntl.h>
#include <wordexp.h>
#include "common.h"

#define OPTYPE_SET(t) (t != -1)
void print_opts(struct kjob_info *opts);
int parse_opts(int argc, char *argv[], struct kjob_info *jobinfo);
void *do_syscall(void *rawinput);
#endif
