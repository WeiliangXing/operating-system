#ifndef A3_COMPRESS_H
#define A3_COMPRESS_H

#include "common.h"

int hw3_compress(struct kjob_info *kjob);
	
/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#endif
