/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "amfs.h"
#include "amfs_ioctl.h"

//test local functions
int ioctl_ops(struct file *file, unsigned long arg, int mode);

static ssize_t amfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	int temp;
	struct super_block *sb;
	struct patterns *patptr;
	char *name = "user.safety_type";
	char *value = NULL;
	char *val = NULL;
	int label;
	int marker = 0; // bad: 1, good: 2, undefined: 0

	sb = file->f_path.dentry->d_sb;
	patptr = &(AMFS_SB(sb)->pattdb);

	val = kmalloc(1, GFP_KERNEL);
	if(IS_ERR(val)){
			err = -ENOMEM;
			printk("MEMORY is not enough!\n");
			goto out;
	}
	label = amfs_main_iops.getxattr(dentry, name, val, 1);
	if(label > 0){ // the file has previous setup EA
		if(!strncmp(val, "1",1)){// 1 means bad file
			printk("EA: bad file!\n");
			err = -1;
			marker = 1;
		}
		if(!strncmp(val, "0",1)){// 1 means bad file
			printk("EA: good file!\n");
			marker = 2;
		}

	}else{//the file may haven't setup EA yet
		marker = 0;
	}
	kfree(val);

	if(marker == 0){//undefined
		lower_file = amfs_lower_file(file);
		err = vfs_read(lower_file, buf, count, ppos);
		/*begin bad/good file filtering*/
		temp = amfs_strcmp(patptr, buf);
		if(temp == 1) {//bad file
			printk("bad file!\n");
			value = "1";
			err = -1;
		}
		if(temp == 0) {
			printk("safe file!\n");
			value = "0";
		}
		label = amfs_main_iops.setxattr(dentry, name, value, 1,0);
	}
	if(marker == 2){
		lower_file = amfs_lower_file(file);
		err = vfs_read(lower_file, buf, count, ppos);
	}

	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));

	out:
	return err;
}

static ssize_t amfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	int temp;
	struct super_block *sb;
	struct patterns *patptr;
	char *val = NULL;
	int label;
	char *name = "user.safety_type";

	sb = file->f_path.dentry->d_sb;
	patptr = &(AMFS_SB(sb)->pattdb);

	val = kmalloc(1, GFP_KERNEL);
	if(IS_ERR(val)){
			err = -ENOMEM;
			printk("MEMORY is not enough!\n");
			goto out;
	}
	label = amfs_main_iops.getxattr(dentry, name, val, 1);
	if(label > 0){ // the file has previous setup EA
		if(!strncmp(val, "1",1)){// 1 means bad file
			printk("EA: bad file!\n");
			err = -1;
			kfree(val);			
			goto out;
		}
		if(!strncmp(val, "0",1)){// 1 means bad file
			printk("EA: good file!\n");
		}
		kfree(val);
	}else{
		kfree(val);
	}

	/*begin bad/good write buffer filtering*/
	temp = amfs_strcmp(patptr, (char *)buf);
	if(temp == 1) {
		printk("bad buffer!\n");
		err = -1;
		goto out;
	}
	if(temp == 0) {printk("safe buffer!\n");}


	lower_file = amfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(dentry->d_inode,
					file_inode(lower_file));
	}
	printk("write file goes here!\n");
	
	out:
	return err;
}

static int amfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = amfs_lower_file(file);
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));
	return err;
}

static long amfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	switch(cmd){
		case IOCTL_ADD:
			printk("mode is %i\n", 0);
			err = ioctl_ops(file, arg, 0);
			break;
		case IOCTL_REMOVE:
			printk("mode is %i\n", 1);
			err = ioctl_ops(file, arg, 1);
			break;
		case IOCTL_LIST:
			printk("mode is %i\n", 2);
			err = ioctl_ops(file, arg, 2);
			printk("finish write out file for listing\n");
			break;
		case IOCTL_SIZE:
			printk("mode is %i\n", 3);
			err = ioctl_ops(file, arg, 3);
			break;
		case IOCTL_PASSWD:
			printk("mode is %i\n", 4);
			err = ioctl_ops(file, arg, 4);
			break;
		default:
			goto out;
	}
	// printk("after mode, the err is: %i\n", err);
	if(err < 0)
		goto out;


	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);
	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
	err = 0; // need to force this
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long amfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

int ioctl_ops(struct file *file, unsigned long arg, int mode){

	struct user_pattern *user_pat = NULL;
	char *str = NULL;
	long err = 0;
	struct super_block *sb;
	struct patterns *patptr;
	static int count;

	sb = file->f_path.dentry->d_sb;
	patptr = &(AMFS_SB(sb)->pattdb);

	if(mode == 4){
		if(strcmp(patptr->passwd, (char *)arg) != 0){
			err = -1;
		}else
			err = 1;
		goto out;
	}

	if(count == patptr->pats_len)
		count = 0;

	if(mode == 2){
		char **base = patptr->pat;
		if(copy_to_user((char *)arg, *(base + count), strlen(*(base + count))+1)){
			err = -EFAULT;
			printk("Fail to copy from kernel space to user space!\n");
		}
		count++;
		goto out;
	}
	if(mode == 3){
		*(int *)arg = patptr->pats_len;
		goto out;
	}

	if(mode == 0 || mode == 1){
		user_pat = kmalloc(sizeof(struct user_pattern), GFP_KERNEL);
		if(IS_ERR(user_pat)){
			err = -ENOMEM;
			printk("MEMORY is not enough!\n");
			goto out;
		}
		if(copy_from_user(user_pat, (struct user_pattern *)arg,
		 sizeof(struct  user_pattern))){
			err = -EFAULT;
			printk("Fail to copy from user space to kernel space!\n");
			goto free_pat;
		}
		str = user_pat->pat;
	}

	if(mode == 0){

		err = amfs_add_pat(&(AMFS_SB(sb)->pattdb), str);

		if(err < 0)
			goto free_pat;
		
		err = amfs_crypt(patptr, 0);
		if(err < 0)
			goto free_pat;
		err = write_pattern_file(&(AMFS_SB(sb)->pattdb), AMFS_SB(sb)->pattdb.db_dir);

		// printk("finish write for add\n");
		if(err < 0)
			goto free_pat;

		err = amfs_crypt(patptr, 1);
		if(err < 0)
			goto free_pat;
	}
	if(mode == 1){
		err = amfs_remove_pat(patptr, str);
		if(err < 0)
			goto free_pat;
		err = amfs_crypt(patptr, 0);
		if(err < 0)
			goto free_pat;
		err = write_pattern_file(patptr, patptr->db_dir);
		// printk("finish write for remove\n");
		if(err < 0)
			goto free_pat;
		err = amfs_crypt(patptr, 1);
		if(err < 0)
			goto free_pat;
	}

	free_pat:
		kfree(user_pat);
	out:
		return err;
}

static int amfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = amfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "amfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!AMFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "amfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &amfs_vm_ops;

	file->f_mapping->a_ops = &amfs_aops; /* set our aops */
	if (!AMFS_F(file)->lower_vm_ops) /* save for our ->fault */
		AMFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}


static int amfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	struct dentry *dentry;
	char *val = NULL;
	int label;
	char *name = "user.safety_type";

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	//====
	// check whether the file is labeled bad
	dentry = file->f_path.dentry;

	val = kmalloc(1, GFP_KERNEL);
	if(IS_ERR(val)){
			err = -ENOMEM;
			printk("MEMORY is not enough!\n");
			goto out_err;
	}
	label = amfs_main_iops.getxattr(dentry, name, val, 1);
	if(label > 0){ // the file has previous setup EA
		if(!strncmp(val, "1",1)){// 1 means bad file
			printk("EA: bad file!\n");
			err = -1;
			kfree(val);
			goto out_err;
		}
		if(!strncmp(val, "0",1)){// 1 means bad file
			printk("EA: good file!\n");
		}
		kfree(val);

	}else{
		kfree(val);
	}

	file->private_data =
		kzalloc(sizeof(struct amfs_file_info), GFP_KERNEL);
	if (!AMFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link amfs's file struct to lower's */
	amfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = amfs_lower_file(file);
		if (lower_file) {
			amfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		amfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(AMFS_F(file));
	else
		fsstack_copy_attr_all(inode, amfs_lower_inode(inode));
out_err:
	return err;
}

static int amfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int amfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = amfs_lower_file(file);
	if (lower_file) {
		amfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(AMFS_F(file));
	return 0;
}

static int amfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = amfs_lower_file(file);
	amfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	amfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int amfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

static ssize_t amfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_read)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

static ssize_t amfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_write)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

/*
 * AMFS cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t amfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = amfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * AMFS read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
amfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

/*
 * AMFS write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
amfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations amfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= amfs_read,
	.write		= amfs_write,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.mmap		= amfs_mmap,
	.open		= amfs_open,
	.flush		= amfs_flush,
	.release	= amfs_file_release,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
	.aio_read	= amfs_aio_read,
	.aio_write	= amfs_aio_write,
	.read_iter	= amfs_read_iter,
	.write_iter	= amfs_write_iter,
};

/* trimmed directory options */
const struct file_operations amfs_dir_fops = {
	.llseek		= amfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= amfs_readdir,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.open		= amfs_open,
	.release	= amfs_file_release,
	.flush		= amfs_flush,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
};
