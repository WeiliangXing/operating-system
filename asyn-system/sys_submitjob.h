/*
 *  This header file is only used with sys_submit.c
 *  Therefore No worry about conflict in declaration
 *  Bring stuff from sys_submit.c for compact code
 */
#ifndef _HW_SYS_SUBMITJOB_H
#define _HW_SYS_SUBMITJOB_H

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include "common.h"     /* shared data structure between kernel module and userland */
#include "thread.h"     /* thread functions and helpers */
#include "utils.h" /* small library of handy str functions */
#include "features.h"

asmlinkage extern long (*sysptr)(void *arg);
/* 
 * simple prechecks of userland struct  
 */
static int precheck_usargs(struct kjob_info __user *data) {
    int rc = 0;
    if (data->optype == OP_LIST_JOBS)
      return 0;

    if (!data || !data->filename || (data->optype != OP_CHECKSUM && !data->outfilename) || data->optype == -1 || !data->opts) {
		printk("User data is invalid\n");
        return -EINVAL;
    }
    if(strlen(data->filename) > PATH_MAX || strlen(data->outfilename) > PATH_MAX) {
        rc = -ENAMETOOLONG;
        goto out;
    }
 out:
    return rc;
}


#endif
