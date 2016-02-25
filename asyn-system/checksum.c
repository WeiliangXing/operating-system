#include <linux/slab.h> /* kmalloc */
#include <asm/uaccess.h> /* copy_from_user */
#include <linux/fs.h> /* for filp_open */

/*for hash */
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/delay.h>

#include "strops.h"
#include "common.h"
#include "utils.h"
#include "features.h"

/* copy checksum struct from user to kernel*/
int copy_checksum_struct(struct kjob_info *kjob,  struct kjob_info __user *ujob) {
	struct checksum_args *kopts, *uopts;
	int rc = 0;
	/* Error check */
    if (ujob == NULL)
        return -EFAULT;

    kjob->opts = kzalloc(sizeof(struct checksum_args), GFP_KERNEL);
	if (!kjob->opts) {
		rc = -ENOMEM;
		return rc;
	}

	kopts = (struct checksum_args *)kjob->opts;
	uopts = (struct checksum_args *)ujob->opts;

    /*check NULL condition for checksum struct*/
    if(uopts->alg == NULL){
        printk("algorithm for checksum cannot be null !\n");
        rc  = -EINVAL;
        goto errout;
    }

    printk("copy issue starts here !\n");
	if ((rc = copy_user_str(&kopts->alg, uopts->alg)) < 0) {
        goto errout;
    }
	if (rc == 0)
		return rc;
 errout:
	free_checksum_opts(kjob);
	return rc;
}

/*copy checksum options from user to kernel*/
int kcopy_checksum_info(struct kjob_info *dst, struct kjob_info *src) {
	struct checksum_args *dopts, *sopts; /*dest opts & src opts */
	int rc = 0;
	if (!(dst->opts = kzalloc(sizeof(struct checksum_args), GFP_KERNEL))) {
		return -ENOMEM;
	}

	dopts = (struct checksum_args *)dst->opts;
	sopts = (struct checksum_args *)src->opts;

	if (!(dopts->alg = kstrdup(sopts->alg, GFP_KERNEL))) {
		rc = -ENOMEM;
		goto errout;
	}
 errout:
	if (rc)
		free_checksum_opts(dst);	
	
	free_checksum_opts(src);
	return rc;
}

/*free checksum options*/
void free_checksum_opts(struct kjob_info *job) {
	struct checksum_args *opts;
	if (!job) return;
	if (!job->opts) return;
	
	opts = (struct checksum_args *)job->opts;
	if (opts->alg)
		kfree(opts->alg);

	kfree(job->opts);
	job->opts = NULL;
}

/*calculate checksum of the input file*/
int get_checksum(void *jobinforaw) {
    int rc = 0;
    struct file *readFilePtr;
    mm_segment_t oldfs;
    char *bytes;
    char *hexstr=NULL;
    struct hash_desc desc;
    size_t inputInodeSize = 0;/* for get size of input file */

	struct kjob_info *jobinfo = (struct kjob_info *)jobinforaw;
    struct checksum_args *opts = (struct checksum_args *)jobinfo->opts;
	
    struct crypto_hash *tfm;
	struct file *fpout = NULL;

	struct file *pipe = jobinfo->pipe;

    readFilePtr = filp_open(jobinfo->filename, O_RDONLY, 0);
    if(!readFilePtr || IS_ERR(readFilePtr)){
        printk("Open input file '%s' error: %d\n", jobinfo->filename,
			   (int)PTR_ERR(readFilePtr));
        rc = PTR_ERR(readFilePtr);
        readFilePtr = NULL;
        return rc;
    }
    rc = isInFileValid(readFilePtr);
    if(rc < 0)
        goto close_input_file;

    inputInodeSize = i_size_read(readFilePtr->f_path.dentry->d_inode);

    bytes = (char *)kmalloc(PAGE * sizeof(char) + 1, GFP_KERNEL);
    if(IS_ERR(bytes)){
        rc = -ENOMEM;
        goto close_input_file;
    }
    oldfs = get_fs();
    set_fs(get_ds());

    /*begin hash */
    tfm = crypto_alloc_hash(opts->alg, 0, CRYPTO_ALG_ASYNC);
    if(!tfm || IS_ERR(tfm)){
		printk("can't resolve\n");
        rc = -PTR_ERR(tfm);
        goto set_oldfs;
    }
    desc.tfm = tfm;
    desc.flags = 0;

    rc = crypto_hash_init(&desc);
    if(rc){
        rc = -EKEYREJECTED;
        goto free_hash;
    }

    while((inputInodeSize - readFilePtr->f_pos) > 0) {
        struct scatterlist sg;
        if(inputInodeSize - readFilePtr->f_pos >= PAGE) {
            rc = readFilePtr->f_op->read(readFilePtr, bytes, PAGE, &readFilePtr->f_pos);
            if(rc < 0){
                rc = -EPERM;
                printk("Read Blocks failed!\n");
                goto free_hash;
            }
            bytes[PAGE] = '\0';

            /*update hash*/
            sg_init_one(&sg, bytes, PAGE);
            rc = crypto_hash_update(&desc, &sg, PAGE);
            if(rc < 0) {
                rc = -EKEYREJECTED;
                goto free_hash;
            }

        } else {
            int rest = inputInodeSize - readFilePtr->f_pos;
            rc = readFilePtr->f_op->read(readFilePtr, bytes, rest, &readFilePtr->f_pos);
            if(rc < 0){
                rc = -EPERM;
                printk("Read Blocks failed!\n");
                goto free_hash;
            }
            bytes[rest] = '\0';

            /*update hash*/
            sg_init_one(&sg, bytes, rest);
            rc = crypto_hash_update(&desc, &sg, rest);
            if(rc < 0) {
                rc = -EKEYREJECTED;
                goto free_hash;
            }
        }
    }

    rc = crypto_hash_final(&desc, opts->checksum);
    if(rc){
        rc = -EKEYREJECTED;
        goto free_hash;
    }

    /*end hash*/
	print_hexdump(opts->checksum);
    printk("alg is %s\n", opts->alg);
	
	send_info(pipe, "Checksum is:");
    hexstr = kmalloc(96, GFP_KERNEL); /*check ENOMEM*/
    
    /* ref: http://lxr.free-electrons.com/source/lib/hexdump.c#L108 
     * 16 is number of bytes to be displayed, 1 is single row, 96 is size of hexstr
     */
    hex_dump_to_buffer(opts->checksum, strlen(opts->checksum), 16, 1, hexstr, 96, true);
    send_info(pipe, hexstr);
    if (hexstr)
        kfree(hexstr);

	/* if output file is set, write to it */
	if (jobinfo->outfilename) {
		fpout = filp_open(jobinfo->outfilename, O_WRONLY | O_CREAT | O_TRUNC,
						  S_IRUSR | S_IWUSR);
		if (!fpout || IS_ERR(fpout)) {
			printk("Bad open of output file: %d\n", (int)PTR_ERR(fpout));
			rc = PTR_ERR(fpout);
			if (rc == -EISDIR) 
				printk("The output file cannot be a directory\n");
			goto free_hash;
		}

		if (!fpout->f_op->write) {
			printk("File system doesn't allow writes\n");
			rc = -EACCES;
			goto free_hash;
		}
		printk("writing to filename %s\n", jobinfo->outfilename);
		write_file(fpout, opts->checksum, strlen(opts->checksum));
	}	

 free_hash:
	if (fpout)
		filp_close(fpout, NULL);
    crypto_free_hash(tfm);
 set_oldfs:
    set_fs(oldfs);
    kfree(bytes);
 close_input_file:
    filp_close(readFilePtr, NULL);
    return rc;
}
