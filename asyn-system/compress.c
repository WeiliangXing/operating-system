/*
  Compress (or decompress) file F1 with algorithm C.  Options include
  overwriting/deleting original file, or renaming file F1 to F2.  Return an
  error code or success code.  Optionally you may return the size of the
  compressed file.

  first case: compress/decompress with no options
*/

#include <linux/zlib.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include "common.h"
#include "strops.h"
#include "utils.h"
#include "features.h"

#ifdef PAGE_SIZE
#undef PAGE_SIZE
#define PAGE_SIZE 25
#endif

char * temp_filename = "/tmp/temp_compress";


int rename_from_tmp(const char *tmp, const char *dst);
int rename_wrapper(struct path lower_old_path, struct path lower_new_path);

/*main function to compress the input file*/
int
hw3_compress(struct kjob_info * kjob)
{
	struct compress_args*  c_args = NULL;
	char* infile = NULL;
	char* outfile = NULL;
	struct file * file_infile = NULL;
	struct file * file_outfile = NULL;
	mm_segment_t prev_fs;
	loff_t pos_in = 0, pos_out = 0;
	unsigned char *buff = NULL;
	unsigned char *out_buff = NULL;
	int read_amount = 0, flush = 0, workspace_size = 0, deflate_init_flag = 0,inflate_init_flag = 0, 
	    err = 0, z_err = 0, delete = 0;
	z_stream strm;
	strm.workspace = NULL;

	if (!kjob)
		return -EINVAL;
	if (!(c_args = (struct compress_args *)kjob->opts))
		return -EINVAL;
	infile = kjob->filename;
	outfile = kjob->outfilename;
	
	file_infile = filp_open(kjob->filename, O_RDWR, 0);
	if(!file_infile || IS_ERR(file_infile)){
		err = PTR_ERR(file_infile);
		file_infile = NULL;
		goto out;
	}
	err = isInFileValid(file_infile);
	if(err){
		UDBG;
		goto out;
    }
	/*create if don't exist, if same file as original file, throw error */
	if(c_args->rename){
		file_outfile = filp_open(outfile, O_CREAT |  O_RDWR, S_IWUSR | S_IRUSR);
		if(IS_ERR(file_outfile)){
			err = PTR_ERR(file_outfile);
			file_outfile = NULL;
			goto out;
		}
		/*must be different names */
		if(!strcmp(infile, outfile)){
			err = -EINVAL;
			goto out;
		}
		/*must be different inodes */
		/*diff names can point to the same thing */
		if(file_outfile->f_inode->i_ino == file_infile->f_inode->i_ino){
			err = -EINVAL;
			goto out;
		}
	}
	
	/*overwrite or new file */
	file_outfile = filp_open(outfile, O_CREAT | O_RDWR, S_IWUSR | S_IRUSR);
	if(IS_ERR(file_outfile)){
		err = PTR_ERR(file_outfile);
		file_outfile = NULL;
		goto out;
	}

	if(file_outfile->f_inode->i_ino == file_infile->f_inode->i_ino){
		delete = 1;
		/*create temp file to write to */
		filp_close(file_outfile, 0);
		file_outfile = filp_open(temp_filename, O_CREAT | O_RDWR,  S_IRUSR | S_IWUSR);
		if(IS_ERR(file_outfile)){
			err = PTR_ERR(file_outfile);
			file_outfile = NULL;
			goto out;
		}
	}

	err = isOutFileValid(file_outfile);
	if(err){
		UDBG;
		goto out;
	}

	buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(!buff){
		err = -ENOMEM;
		goto out;
	}
  
	/*out_buff must be slightly larger */
	out_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(!out_buff){
		err = -ENOMEM;
		goto out;
	}

	if(c_args->op == DO_COMPRESS){
		/*next_in, avail_in, next_out, and avail_out must be initialized before deflate */
		workspace_size = zlib_deflate_workspacesize (MAX_WBITS, MAX_MEM_LEVEL);
		strm.workspace = kmalloc(workspace_size, GFP_KERNEL);
		if(!strm.workspace){
			err = -ENOMEM;
			goto out;
		}
    
		/*provide defaults in case the user does not specify all the required options */
		/*Uninitialized values will result in undefined behavior! */
		if(!c_args->zlib_compression_level)
			c_args->zlib_compression_level = Z_DEFAULT_COMPRESSION;
		if(!c_args->zlib_method)
			c_args->zlib_method = Z_DEFLATED;
		if(!c_args->zlib_window_bits)
			c_args->zlib_window_bits = 15;
		if(!c_args->zlib_mem_level)
			c_args->zlib_mem_level = 8;
		if(!c_args->zlib_strategy)
			c_args->zlib_strategy = Z_DEFAULT_STRATEGY;
	
		err = zlib_deflateInit2(&strm, c_args->zlib_compression_level, 
								c_args->zlib_method,
								c_args->zlib_window_bits,
								c_args->zlib_mem_level,
								c_args->zlib_strategy);
		if(err != Z_OK){
			UDBG;
			if (err == Z_MEM_ERROR){
				err = -ENOMEM;
				goto out;
			}
			else if (err == Z_STREAM_ERROR){
				/* invalid compression level */
				UDBG;
				err = -EINVAL;
				goto out;
			}
			else{
				err = -EINVAL;
				UDBG;
				goto out;
			}
		}
		/*indicate that we got to the point where we need to use deflateEnd (free data structures private to stream) */
		/*no pointer to check against so we have to do this instead */
		deflate_init_flag = 1;        

		/*Two loops needed because reading does correspond to output from deflate in a one to one ratio */
		do {
      
			prev_fs = get_fs();
			set_fs(KERNEL_DS);
			read_amount  =  vfs_read(file_infile, buff, PAGE_SIZE, &pos_in);
			set_fs(prev_fs);    
			if(read_amount < 0 ){
				UDBG;
				err = read_amount;
				goto out;
			}
    
      
			flush = read_amount != 0 ? Z_NO_FLUSH : Z_FINISH;
       
			strm.next_in = buff;
			strm.avail_in = read_amount;

			do{

				strm.next_out = out_buff;
				strm.avail_out = PAGE_SIZE;
	
				z_err = zlib_deflate(&strm, flush);
				prev_fs = get_fs();
				set_fs(KERNEL_DS);
				/*read amount should actually be PAGE_SIZE - strm.avail_out */
				err = vfs_write(file_outfile, out_buff, PAGE_SIZE - strm.avail_out, &pos_out);    
				if(err < 0){
					printk("Write error occurred \n");
					printk("Error value: %d", err);
					goto out;
				}
				set_fs(prev_fs);    
				/*while we've got data to consume */
			}while(strm.avail_out == 0);
      
			/*while we are not done reading */
		} while(flush != Z_FINISH);
		
		err = 0;
	}

	if(c_args->op == DO_DECOMPRESS) {
		workspace_size = zlib_inflate_workspacesize();
		strm.workspace = NULL;
		strm.workspace = kmalloc(workspace_size, GFP_KERNEL);
		if(!strm.workspace){
			err = -ENOMEM;
			goto out;
		}
		strm.next_in = buff;
		strm.avail_in = 0;
		err = zlib_inflateInit(&strm);
		if(err != Z_OK) {
			if (err == Z_MEM_ERROR) {
				err = -ENOMEM;
				goto out;
			}
			else if (err == Z_STREAM_ERROR) {
				/* invalid compression level */
				err = -EINVAL;
				goto out;
			}
			else
				err = -EINVAL;
		}
		inflate_init_flag = 1;

		do {
			prev_fs = get_fs();
			set_fs(KERNEL_DS);
			read_amount = vfs_read(file_infile, buff, PAGE_SIZE, &pos_in);
			if(read_amount < 0 ){
				err = read_amount;
				goto out;
			}
			set_fs(prev_fs);    

			strm.next_in = buff;
			strm.avail_in = read_amount;
      
			do {
				strm.next_out = out_buff;
				strm.avail_out = PAGE_SIZE;    
				z_err = zlib_inflate(&strm, Z_NO_FLUSH);
				if(z_err == Z_NEED_DICT || z_err == Z_DATA_ERROR){
					err = -EINVAL;
					goto out;
				}
				if(z_err == Z_MEM_ERROR){
					err = -ENOMEM;
					goto out;
				}
				prev_fs = get_fs();
				set_fs(KERNEL_DS);
				err = vfs_write(file_outfile, out_buff, PAGE_SIZE - strm.avail_out, &pos_out);    
				if(err < 0){
					printk("Write error occurred \n");
					printk("Error value: %d", err);
					goto out;
				}
				set_fs(prev_fs);    
			} while(strm.avail_out == 0 );
      
		} while(z_err != Z_STREAM_END);

		err = 0;
	}

	if(delete) {
	         rename_from_tmp(temp_filename, kjob->filename);
	}
	if(c_args->rename) {
	         vfs_unlink(file_infile->f_path.dentry->d_parent->d_inode, file_infile->f_path.dentry, NULL);
	}

 out:
	/* zlib */
	if( (c_args->op == DO_COMPRESS) && deflate_init_flag){
		if( Z_OK != zlib_deflateEnd(&strm))
			printk("zlib_deflateEnd error \n");
	}
	if(c_args->op == DO_DECOMPRESS && inflate_init_flag){    
		if ( Z_OK != zlib_inflateEnd(&strm))
			printk("zlib_inflateEnd error \n");
	}
	if(strm.workspace)
		kfree(strm.workspace);
	
	return err;  
}


/*rename the tmp file*/
int rename_from_tmp(const char *tmp, const char *dst) {
    struct file *filp_old, *filp_new;
    struct inode *old_inode;
    struct dentry *old_dentry;
    struct inode *new_inode;
    struct dentry *new_dentry;

    int res = 0;

    if (!tmp || !dst)
		return -EINVAL;
    filp_old = filp_open(tmp, O_RDONLY, 0);
    if (!filp_old || IS_ERR(filp_old)){
		res = PTR_ERR(filp_old);
		return res;
    }
    filp_new = filp_open(dst, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (!filp_new || IS_ERR(filp_new)) {
		printk("Bad open of output file: %d\n", (int)PTR_ERR(filp_new));
		res = PTR_ERR(filp_new);
		BUG_ON(res == -EISDIR);
		filp_close(filp_old, NULL);
		return res;
    }

    old_inode = file_inode(filp_old);
    old_dentry = filp_old->f_path.dentry;
    new_inode = file_inode(filp_new);
    new_dentry = filp_new->f_path.dentry;

    if ((res = rename_wrapper(filp_old->f_path,filp_new->f_path))) {
		printk("Couldn't rename it\n");
    }

    filp_close(filp_old, NULL);
    filp_close(filp_new, NULL);
    return res;
}

int rename_wrapper(struct path lower_old_path, struct path lower_new_path) {
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;

	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry, lower_new_dir_dentry->d_inode, lower_new_dentry, NULL, 0);
	if (err) {
		goto out;
	}
 out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	return err;
}

/*free compress options*/
void free_compress_opts(struct kjob_info *job) {
	struct encrypt_args* opts;
	if (!job) return;
	if (!job->opts) return;
	
	opts = (struct encrypt_args *)job->opts;
	
	kfree(opts);
	job->opts = NULL;
}

/*copy compress struct from user to kernel*/
int copy_compress_struct(struct kjob_info *kjob,  struct kjob_info __user *ujob) {
	struct compress_args *kopts, *uopts;
	int rc = 0;
	
    /* Error check */
    if (!ujob || !kjob->opts) /* an indirect check of ujob->opts */
        return -EFAULT;
	kjob->opts = NULL;
	if (!(kjob->opts = kmalloc(sizeof(struct compress_args), GFP_KERNEL))) {
		rc = -ENOMEM;
		goto errout;
	}

	kopts = (struct compress_args *)kjob->opts;
	uopts = (struct compress_args *)ujob->opts;
	
    if (copy_from_user(kopts, uopts, sizeof(struct compress_args))) {
        rc = -EFAULT;
        goto errout;
    }	

    if (kopts->op != DO_COMPRESS && kopts->op != DO_DECOMPRESS) {
	    rc = -EINVAL;
	    goto errout;
    }
    
    if (rc == 0) return 0;

 errout:
	if (kjob->opts)
		kfree(kjob->opts);
	return rc;
}

/*copy compress options from user to kernel*/
int kcopy_compress_info(struct kjob_info *dst, struct kjob_info *src) {
	struct compress_args *dopts, *sopts; //dest opts & src opts
	int rc = 0;
	if (!(dst->opts = kzalloc(sizeof(struct compress_args), GFP_KERNEL)))
		return -ENOMEM;
	
	dopts = (struct compress_args *)dst->opts;
	sopts = (struct compress_args *)src->opts;

	dopts->op = sopts->op;
	/* errout: */
	if (rc) {
		if (!dopts) {
			kfree(dopts);
		}
	}
	
	return rc;
}
