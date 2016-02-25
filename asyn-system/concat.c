#include "common.h"
#include "features.h"
#include "concat_extra.h"

/*
 * function to handle files concatenation
 * concat does not touch passed pointer of job
 */
int concat_files(struct kjob_info* job) {    /* job is a pointer in kernel space */
	int rc = 0, i;

	struct concat_args *kopts = job->opts;
	struct file *pipe = job->pipe;
	rc = is_concat_input_valid(kopts);
    printk("validation returns %d\n", rc);
	if(rc < 0) 
		goto out;

   /* first file */
   printk("input: %s, output: %s\n", job->filename, job->outfilename);
   rc = concat_single_file(job->filename, job->outfilename);
   /* rest */
   for(i = 0; i < kopts->inf_num; i++) {
        printk("processing concat for file %d: %s\n", i+1, kopts->in_files[i]);
        rc = concat_single_file(kopts->in_files[i], job->outfilename);
 		if(rc < 0)
			goto out;
    }

	send_info(pipe, "Concat operation complete.\nsend_err demo:");
    send_err(pipe, -ENOENT, "this is our custom err prop string %s %d %c\n", job->outfilename, kopts->inf_num, 'Z');

out:
    if (rc<0)
        send_errc(pipe, rc);
    return rc;
}

/* 
function to concat single input file into output file;
new file will be attached to the end of same output file;
*/
int concat_single_file(const char *in_dir, const char *out_dir){
	int rc = 0;
	struct file *readFilePtr = NULL;/*for input file pointer.*/
	struct inode *inputIn = NULL;/*for get inode of input file*/
	struct inode *outputIn = NULL;/*or get inode of output file*/
	size_t inputInodeSize = 0;/* for get size of input file*/
	umode_t inputInodeMode = 0;/*for get mode of input file */
	umode_t outputInodeMode = 0;/*for get mode of output file */

	struct file *writeFilePtr = NULL;/*for output file pointer.*/
	mm_segment_t oldfs;
	char *bytes;/* bytes from input filem*/

	readFilePtr = filp_open(in_dir, O_RDONLY, 0);   /* mode changed from O_RDONLY */
	if(!readFilePtr || IS_ERR(readFilePtr)) {
        rc = readFilePtr?PTR_ERR(readFilePtr):-EFAULT;
		printk("Open input file error: %d\n", rc);
		readFilePtr = NULL;
		goto out; 
	}

	/*check whether has read permission: */		
	if(!readFilePtr->f_op->read){
		printk("Read input file Permission Denied!\n");
		rc = -EPERM;
		goto close_input_file;
	}
	/*get input file size and check whether null*/
	inputIn = readFilePtr->f_path.dentry->d_inode;
	inputInodeSize = i_size_read(inputIn);

	if(inputInodeSize <= 0){
		printk("Error: input file's size is %zu\n",inputInodeSize);
		rc = -EPERM;
		goto close_input_file;
	}
	/*check whether input file is regular*/
	inputInodeMode = inputIn->i_mode;
	if(S_ISREG(inputInodeMode) == 0){
		printk("Error: The file is not regular: input file.\n");
		rc = -EISDIR;
		goto close_input_file;
	}
	/*check whether can open:	*/	
	writeFilePtr = filp_open(out_dir, O_WRONLY|O_CREAT|O_APPEND, 0644);
	if(!writeFilePtr || IS_ERR(writeFilePtr)){
		printk("Open output file error: %d\n", (int)PTR_ERR(writeFilePtr));
        rc = writeFilePtr?PTR_ERR(writeFilePtr):-EFAULT;
		writeFilePtr = NULL;
		goto close_input_file;
	}
	/*check whether could be write*/
	if(!writeFilePtr->f_op->write){
		printk("Read output file Permission Denied!\n");
		rc = -EPERM;
		goto close_output_file;
	}
	/*check regularity of the output file*/
	outputIn = writeFilePtr->f_path.dentry->d_inode;
	outputInodeMode = outputIn->i_mode;
	if(S_ISREG(outputInodeMode) == 0){
		printk("Error: The file is not regular: output file.\n");
		rc = -EISDIR;
		goto close_output_file;
	}
	/*step4: deep check whether input/output file equal(relative/absolute)*/
	if(outputIn->i_ino == inputIn->i_ino){
		printk("Error: input and output file are same.\n");
		rc = -EINVAL;
		goto close_output_file;
	}

	bytes = (char *)kmalloc(PAGE_SIZE * sizeof(char) + 1, GFP_KERNEL);
	if(IS_ERR(bytes)){
		rc = -ENOMEM;
		goto close_output_file;
	}

	/*begin read and write*/
	while((inputInodeSize - readFilePtr->f_pos) > 0){
		if(inputInodeSize - readFilePtr->f_pos >= PAGE_SIZE){
		    oldfs = get_fs();
    	    set_fs(KERNEL_DS);
	    	rc = readFilePtr->f_op->read(readFilePtr, bytes, PAGE_SIZE, &readFilePtr->f_pos);
            set_fs(oldfs);
			if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto set_oldfs;
			}
		    oldfs = get_fs();
    	    set_fs(KERNEL_DS);
            rc = writeFilePtr->f_op->write(writeFilePtr, bytes, PAGE_SIZE, &writeFilePtr->f_pos);
	        set_fs(oldfs);
		    if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto set_oldfs;
			}
		} else {
			int rest = inputInodeSize - readFilePtr->f_pos;
		    oldfs = get_fs();
    	    set_fs(KERNEL_DS);
    		rc = readFilePtr->f_op->read(readFilePtr, bytes, rest, &readFilePtr->f_pos);
            set_fs(oldfs);

			if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto set_oldfs;
			}
		    oldfs = get_fs();
    	    set_fs(KERNEL_DS);
			rc = writeFilePtr->f_op->write(writeFilePtr, bytes, rest, &writeFilePtr->f_pos);
            set_fs(oldfs);
			if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto set_oldfs;
			}
		}
	}

	set_oldfs:
		kfree(bytes);
	close_output_file:
		filp_close(writeFilePtr,NULL);
	close_input_file:
		filp_close(readFilePtr, NULL);

	out:
		return rc;
}

int kcopy_concat_info(struct kjob_info *dst, struct kjob_info *src) {
	struct concat_args *dopts = NULL, *sopts = NULL;
	int rc = 0, i;
	
	if (!(dst->opts = kmalloc(sizeof(struct concat_args), GFP_KERNEL))) {
		rc = -ENOMEM;
		goto errout;
	}

	dopts = (struct concat_args *)dst->opts;
	sopts = (struct concat_args *)src->opts;

	memcpy(dopts, sopts, sizeof(struct concat_args));

	dopts->in_files = kzalloc(dopts->inf_num * sizeof(char *), GFP_KERNEL);
    if (!dopts->in_files) {
        rc = -ENOMEM;
        goto errout;
    }

	for(i = 0; i < dopts->inf_num; i++) {
		if (!(dopts->in_files[i] = kstrdup(sopts->in_files[i], GFP_KERNEL)))
			goto free_infiles;
	}
	
free_infiles:
	if (rc)
		free_concat_opts(dst);		
errout:
	/* in any case free source opts */
	free_concat_opts(src);
	return rc;
}

int copy_concat_struct(struct kjob_info *kjob,  struct kjob_info __user *ujob) {
	struct concat_args *kopts, *uopts;
	int rc = 0, i;
	
    /* Error check */
    if (!ujob || !kjob->opts) /* an indirect check of ujob->opts */
        return -EFAULT;
 
    kjob->opts = kmalloc(sizeof(struct concat_args), GFP_KERNEL);
	if (!kjob->opts) {
		rc = -ENOMEM;
		goto errout;
	}

	kopts = (struct concat_args *)kjob->opts;
	uopts = (struct concat_args *)ujob->opts;
	
    if (copy_from_user(kopts, uopts, sizeof(struct concat_args))) {
        rc = -EFAULT;
        goto errout;
    }
	kopts->in_files = NULL;
	
    /*
     * *** Buf fix ***
     *  ALWAYS ALLOCATE IN_FILES BEFORE COPYING IN_FILES[0], [1] ETC.
     *  opts is allocated each time submit job is called
     *  allocated and copied each time to queue
     *  therefore should be freed:
     *  - in producer threadfn right after copying to queue
     *  - in consumer threadfn the one from queue should be freed right after consuming
     */
	/* Important: we zero out all infiles, to check on freeing */
    kopts->in_files = kzalloc(kopts->inf_num * sizeof(char *), GFP_KERNEL);
    if (!kopts->in_files) {
        rc = -ENOMEM;
        goto errout;
    }
	/* Copy rest of input file names */
	for(i = 0; i < kopts->inf_num; i++) {
        if (!(kopts->in_files[i] = kzalloc(PATH_MAX, GFP_KERNEL))) {
            rc = -ENOMEM;
            goto errout;
        }

        if ((rc = resolve_fullpath_from_user(kopts->in_files[i],
											 uopts->in_files[i], O_RDONLY, 0)) < 0) {
            printk("Couldn't copy input filename!\n");
            goto free_optsinfile;
        }
	}	

	/* if successfull do not free anything here,
	   shared kjob will be freed by producer */
	if (rc == 0)
		return rc;

free_optsinfile:
    free_concat_opts(kjob);	
errout:
	return rc;
}

/*free concat options struct*/
void free_concat_opts(struct kjob_info *job) {
	struct concat_args *opts;
	int i;
	if (!job) return;
	if (!job->opts) return;

	opts = (struct concat_args *)job->opts;
	if (opts->in_files) {
		for (i = 0;i < opts->inf_num;i++)
			if (opts->in_files[i])
				kfree(opts->in_files[i]);
        kfree(opts->in_files);		
    }
	kfree(opts);
	job->opts = NULL;
}
