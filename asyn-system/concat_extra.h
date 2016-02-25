/*
 * Header File Guard Added
 */

#ifndef HW3_CONCAT_EXTRA_H
#define HW3_CONCAT_EXTRA_H
#include <linux/slab.h> // kmalloc
#include <linux/uaccess.h> // copy_from_user
#include <linux/fs.h> //for filp_open
#include "utils.h"

int concat_single_file(const char *in_dir, const char *out_dir);

/* 
 * isInputValid function accepts struct myargs as argument, 
checks whether the inputs are legal, including non-null checking,
match checking, same file checking, etc.
The function will return error number if any error occurs, 0 if not.
*/
static int is_concat_input_valid(struct concat_args *ptr) {
	int i;

    if (! ptr->inf_num) /* at least 2 args expected */
        return -EINVAL;
	if(!ptr)
		return -EFAULT;

	for(i = 0; i < ptr->inf_num; i++)
		if(strlen(ptr->in_files[i]) > PATH_MAX)
			return -ENAMETOOLONG;
  return 0;
}

#endif
