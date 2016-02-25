/*
 * Main implementation file for the kernel module
 * Interacts with user level program through submitjob function
 *
 * Copy everything received from user space after verifying arguments
 * Data in user will be dealloacted right after return, i** threads should not
 * use those objects and pointers
 */

#include "sys_submitjob.h" /* share data structure between kernel module functions - all extra declarations are in this header*/

/*
 * copies job info structure from userland
 *  - copy follows every pointer inside (recursively) ** important
 *
 * kjob is retrieved from producer thread, and it allocated during init_thread
 */
int copy_jobinfo_from_user(struct kjob_info *kjob, struct kjob_info __user *ujob) {
    int rc = 0;

    /* Error check */
    if ((!ujob || !ujob->filename || !ujob->outfilename || !ujob->opts) && !(ujob->optype == OP_LIST_JOBS))
        return -EFAULT;
    memset(kjob, 0, sizeof(struct kjob_info)); /* consider error scenarios - how helpful this is */
     /*  more complex checks, try to copy from userland*/
    /* copy_from_user does check access_ok */
    if (copy_from_user(kjob, ujob, sizeof(struct kjob_info))) {
        rc = -EFAULT;
        goto out;
    }

    if(kjob->optype != OP_LIST_JOBS) {
        if (!(kjob->filename = kzalloc(PATH_MAX, GFP_KERNEL))) {
            rc = -ENOMEM;
            goto out;
        }
        if (!(kjob->outfilename = kzalloc(PATH_MAX, GFP_KERNEL))) {
            rc = -ENOMEM;
            goto out;
        }
        
        /* kjob->opts is coming from userland it should not be NULL */
        if ((rc = resolve_fullpath_from_user(kjob->filename, ujob->filename, O_RDONLY, 0))) {
            printk("couldn't copy filename, out\n");
            goto out;
        }
        printk("input file is %s\n", kjob->filename);
        
        switch(kjob->optype) {
        case OP_CHECKSUM:
            if ((rc = copy_checksum_struct(kjob, ujob)) < 0)
                goto out;
            break;
        case OP_CONCAT:
            if ((rc = copy_concat_struct(kjob, ujob)) < 0)
                goto out;
            break;
        case OP_COMPRESS:
            if ((rc = copy_compress_struct(kjob, ujob)) < 0)
                goto out;
            break;
        case OP_CRYPT:
            if((rc = copy_encrypt_struct(kjob, ujob)) < 0)
                goto out;
            break;
        default:
            printk("Feature %d not implemented!\n", kjob->optype);
            goto out;
        }
        /* if all went ok so try creating output file */
        if ((rc = resolve_fullpath_from_user(kjob->outfilename, ujob->outfilename,
                         O_WRONLY | O_CREAT | O_TRUNC,
                         S_IRUSR | S_IWUSR))) {
            goto out;
        }
        printk("outfile is %s\n", kjob->outfilename);
    }
    if (rc == 0)
        return rc;
out:
    if (kjob->outfilename)
        kfree(kjob->outfilename);
    if (kjob->filename)
        kfree(kjob->filename);
    return rc;
}

/*
 * submitjob -
 *  puts the job in proper place for processing (high level)
 *
 * low level desc:
 *  1. get shared producer data
 *  2. copy the job from userland to there
 *  3. wake up producer since job queue is no more empty
 *
 * kjob is shared data and already allocated. We use it as a buffer into which
    we copy userdata. when passing to consumer, we allocate a data-structure
    (queue), and copying data from this buffer.
 *
 * kjob is shared but kjob->opts is not.
 */
asmlinkage long submitjob(void *arg)
{
    int rc = 0;
    struct kjob_info *kjob = NULL, *ujob = (struct kjob_info *)arg;

    if ((rc = precheck_usargs((struct kjob_info *)arg)))
        return rc;

    kjob = get_producer_data();

    if ((rc = copy_jobinfo_from_user(kjob, ujob))) {
        printk("Couldn't copy job from user\n");
        unlock_user_mtx();
        return rc;
    }

    if ((rc = create_pipe(kjob, ujob))) {
        printk("Can't create pipe\n");
        unlock_user_mtx();
        return rc;
    }

    /* create pipe only once and keep it in the job */
    kjob->pipe = resolve_pipe(kjob->pipefd);
    if (IS_ERR(kjob->pipe)) {
        printk("Can't get pipe, err=%d\n", (int)PTR_ERR(kjob->pipe));
        unlock_user_mtx();
        return rc;
    }

    /* rc = send_info(kjob->pipe, "Hello, User\n"); */

    if(kjob->optype == OP_LIST_JOBS) {
        if (kjob->jobid == 0)
            u_print_queue(kjob);
        else
            remove_job_from_queue(kjob);
        unlock_user_mtx();
        return rc;
    }
    
    /* after checks passed kernel d-s to producer */
    wake_up_producer();
    
    return rc;
}

/*
 *  Consumer thread and producer threads are created here
 *  Do any additional initialization here
 *  and initialization required for the system call
 */
static int __init init_sys_submitjob(void)
{
    int rc;
    printk("installed sys_submitjob module\n");    

    if ((rc = init_messaging()))
        return rc;    
    if ((rc = hw3_init_kthread()))
        return rc;    
    
    if (sysptr == NULL)
        sysptr = submitjob;
    return rc;
}

static void  __exit exit_sys_submitjob(void)
{
    if (sysptr != NULL)
        sysptr = NULL;
    hw3_destroy_kthread();
    free_messaging();
    
    printk("removed sys_submitjob module\n");
}


MODULE_AUTHOR("TEAM-HW3");
MODULE_DESCRIPTION("OS-HW3 - producer consumer");
MODULE_LICENSE("GPL");

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);

