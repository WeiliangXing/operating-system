#include <linux/fs.h>
#include <linux/file.h>
#include <linux/limits.h>
#include "utils.h"
#include "common.h"

/* copies path from user to kernel and resolves the path
  into a full path */
int resolve_fullpath_from_user(char *dst, char __user *src,
							   int flags, int mode) {
	struct file* filp = NULL;
	/*kpath buffer is needed to hold copy of user and open the file*/
	char *kpath = NULL;
	/*buf is auxilliary and helps to get full dentry path */
	char *buf = NULL; /* for resolving */
	/*tmp is also temporary and contains the full dentry path while file is open.
	 we just copy from tmp to dst to be able to access filepath after file is closed*/
	char *tmp = NULL;
	int len;
	int rc = 0;

	if (!dst || !src)
		return -EINVAL;
	
	if ((len = strlen(src)) <= 0)
		return -EINVAL;	
	if (len > PATH_MAX)
		len = PATH_MAX;
	
	if (!(kpath = kzalloc(len+1, GFP_KERNEL))) {
		rc = -ENOMEM;
		goto out;
	}
	if (!(buf = kzalloc(PATH_MAX, GFP_KERNEL))) {
		rc = -ENOMEM;
		goto out;
	}
	if (copy_from_user(kpath, src, len+1)) {
		rc = -EFAULT;
		goto out;
	}
	filp = filp_open(kpath, flags, mode);
	if (!filp || IS_ERR(filp)) {
		printk("can't open path %s\n", kpath);
        rc = filp?PTR_ERR(filp):-EFAULT;
		goto out;	
	}
	
	if (!(tmp = dentry_path_raw(filp->f_path.dentry, buf, PATH_MAX))) {
		rc = -ENOMEM;
		goto fout;
	}
	
	memcpy(dst, tmp, strlen(tmp));
 fout:	
	if (filp && !IS_ERR(filp)) {
		filp_close(filp, NULL);
	}   
 out:
	
	if (kpath)
		kfree(kpath);
	if (buf)
		kfree(buf);
	return rc;
}

/*
 * allocates memory to the pointer address provided
 *  - caller is responsible to free this memory
 * copies the NULL terminated user string (checks for errors)
 *  * the function expects NULL temination
 *
 * more details:
 *  if length of the string is more than PATH_MAX only PATH_MAX will be copied
 *
 */
int copy_user_str(char **mod_str, char __user *user_str) {
   int len;
   if (!user_str){
   		return -EINVAL;
   }

   len = strlen(user_str);
   len = len < PATH_MAX? len: PATH_MAX;

   if (len <= 0)
       return -EINVAL;
   *mod_str = kmalloc(len+1, GFP_KERNEL);
   if (!*mod_str)
       return -ENOMEM;
   if (copy_from_user(*mod_str, user_str, len+1))
       return -EFAULT;
   return 0;
}

void print_hexdump(char *hex) {
	int i;
	for(i = 0; i < strlen(hex); ++i) {
		printk("%x", hex[i] & 0xff);
	}
}

/*write file*/
int write_file(struct file *filp, void *buf, int count) {
  mm_segment_t oldfs;
  int bytes;

  oldfs = get_fs();
  set_fs(KERNEL_DS);
  bytes = filp->f_op->write(filp, buf, count, &filp->f_pos);

  set_fs(oldfs);
  return bytes;
}

/* Asynchronous messaging and pipes. */
static struct k_msg *msgbuf = NULL;

/* creates 2 pipe descriptors and assigns them to the k- and ujobs*/
int create_pipe(struct kjob_info* kjob, struct kjob_info* ujob) {
	int *fds;
	int rc;
	struct kjob_info *tmp;

	if (!(tmp = kmalloc(sizeof(struct kjob_info), GFP_KERNEL))) return -ENOMEM;
	
	if (!(fds = kmalloc(2 * sizeof(int), GFP_KERNEL))) {
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = do_pipe_flags(fds, 0))) goto out;
	
	printk("created pipe: (%d,%d)\n", fds[0], fds[1]);

	/* set the write end */
	kjob->pipefd = fds[1];

	/* set the read end */
	if (copy_from_user(tmp, ujob, sizeof(struct kjob_info))) {
		rc = -EFAULT;
		goto out;
	}
	printk("setting the read end %d\n", fds[0]);
	tmp->pipefd = fds[0];
	if (copy_to_user(ujob, tmp, sizeof(struct kjob_info))) {
		rc = -EFAULT;
		goto out;
	}
	rc = 0;
 out:
	if(!fds)
		kfree(fds);
	if (tmp)
		kfree(tmp);
	return rc;
}

/*resolve pipe*/
struct file *resolve_pipe(int pipefd) {
	int rc = 0;
	struct inode *inode;
	struct dentry *dentry;
	struct file *pipe = NULL;
	if (pipefd <= 0)		
		return ERR_PTR(-EINVAL);
 	
	if (!(pipe = fget(pipefd)))
		return ERR_PTR(-EBADFD);

	dentry = pipe->f_path.dentry;
	inode = dentry->d_inode;
	if (!(pipe->f_mode & FMODE_WRITE)) {
		rc = -EINVAL;
		goto out_putf;
	}
	if (!pipe->f_op->write) {
		printk("WARNING: can't use messaging, the file system doesn't allow it\n");		
		rc = -EACCES;
		goto out_putf;
	}

	if (rc == 0)
		return pipe;
 out_putf:
	if (pipe)
		fput(pipe);
	return ERR_PTR(rc);
}

int snprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list args;
    int i;

    va_start(args, fmt);
    i = vsnprintf(buf, size, fmt, args);
    va_end(args);

    return i;
}

/* internal method: sends the structure as it is.
   Prerequirement: all msg fields in msg_buf should be set up */
void send_msg(struct file *pipe) {
	int bytes;
	mm_segment_t oldfs;
	if (!pipe) return;
	if (!msgbuf) return;
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = pipe->f_op->write(pipe, (void *)msgbuf, sizeof(struct k_msg),
							  &pipe->f_pos);	
	set_fs(oldfs);
}

/* accept error code and message format string (that follows with variable number of arguments) */
int send_err(struct file *pipe, int errcode, char *fmt, ...) {
    char *msg = NULL; int len;
 	va_list ap;
	if (!pipe) return 0;	
	if (!msgbuf) return -ENOMEM;

	msgbuf->type = MSG_ERROR | MSG_HASDESC;
	msgbuf->errcode = errcode;

	va_start(ap, fmt);
	msg = kvasprintf(GFP_KERNEL, fmt, ap);
	va_end(ap);
    if (!msg) return -ENOMEM;
	memcpy(msgbuf->desc, msg, ((len = strlen(msg)) > MAX_MSG_LEN-1?MAX_MSG_LEN-1:len));
    if (msg) kfree(msg);
    msgbuf->desc[len] = '\0'; /* enforce null termination */
	send_msg(pipe);
	
	return 0;
}

int send_errc(struct file *pipe, int errcode) {
	memset(msgbuf, 0, sizeof(struct k_msg));
	
	msgbuf->type = MSG_ERROR;
	msgbuf->errcode = errcode;

	send_msg(pipe);	
	return 0;
}

int send_info(struct file *pipe, char *msg) {
	if (!pipe)return 0;	
	if (!msg) return -ENOMEM;

	memset(msgbuf, 0, sizeof(struct k_msg));
	
	msgbuf->type = MSG_HASDESC;
	memcpy(msgbuf->desc, msg, strlen(msg));

	send_msg(pipe);
	
	return 0;
}

/* sends the last message */
void send_finish(struct file *pipe) {
	printk("finish msgbuf addr %d\n", (int)msgbuf);
	memset(msgbuf, 0, sizeof(struct k_msg));	
	msgbuf->type = MSG_FINISH;
	send_msg(pipe);
}

/* sends the last message and closes the pipe */
void terminate_msg(struct file *pipe) {
	printk("Terminate msg,pipe addr=%p\n", (void*)pipe);
	send_finish(pipe);
	printk("filp close %p\n", (void*)pipe);
	if (pipe)
		filp_close(pipe, NULL);
	pipe = NULL;
}

int init_messaging(void) {
	if (!(msgbuf = kmalloc(sizeof(struct k_msg), GFP_KERNEL))) {
		return -ENOMEM;
	}
	return 0;
}

/* closes the messaging channel and releases msg buffer */
void free_messaging(void) {
	printk("msgbuf is freed\n");
	if (msgbuf) {
		kfree(msgbuf);
		msgbuf = NULL;
	}
}
