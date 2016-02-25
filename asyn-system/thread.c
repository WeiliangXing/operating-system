/*
 *  Thread functions and the functions mentioned in the header file
 *  are implementated in this source file
 *
 *  Thread header and source stay highly optimized and they don't need to know
 *  lot about underlying low-level operations: isolate file operations and
 *  strops later and pack into an object
 */

#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/file.h>
#include "common.h"
#include "thread.h"
#include "strops.h"
#include "utils.h"
#include "features.h"

static struct task_struct **consumers;
static struct task_struct *producer_kthread;
static struct kjob_info   *producer_data;

/* q stands for queue */
/* static struct list_head *jobs_q = NULL;  */
static struct list_head *jobs_q[MAX_PRIORITY]; /* q[0] contains jobs with
   priority 1, q[1] contains jobs with priority 2 ans so on..  */

static struct mutex *q_mtx = NULL;
static struct mutex *u_mtx = NULL;

static int jobs_num = 0;
static int g_jobid = 1;

/* Flags are used to tell if a producer is running.
   TODO: use mutex/spinlock when accessing them
*/
static int prod_running = 0;

/* array of state for each consumer. Each state can be 0=waiting,1=running.
   Consumer manages its own state. Producer uses this array to find first available consumer.
   TODO: we need locking to protect structure to be modified from consumers when producer may read it.
*/
static int *consumers_state = NULL;

inline struct kjob_info *get_producer_data(void) {
    mutex_lock(u_mtx);
    return producer_data;
}


void unlock_user_mtx(void) {
    mutex_unlock(u_mtx);
}

inline void wake_up_producer(void) {
    prod_running = 1;
    wake_up_process(producer_kthread);
}

/* not thread-safe: when calling lock q_mtx
 * warning fixed by Atiq - please test
 */
static void print_queue(void) {
    struct queue_item *q_item;
    struct list_head *cur;
    int i = 1;
    int j;
    
    printk("*** print job queue ***\n");
    for (j=0; j<MAX_PRIORITY;j++) {
        if (list_empty(jobs_q[j]))
            continue;
        printk("queue %d:\n", j);
        list_for_each(cur, jobs_q[j]) {
            q_item = list_entry(cur, struct queue_item, item);
            printk("%d)operation type=%d\n", i++, q_item->job->optype);
        }
    }
    printk("***\n");
}

/*
 * Remove job from Kernel Job Queue
 * - no separate thread, done by submit job
 * - linear look up for the job with matching job id and delete
 */
void remove_job_from_queue(struct kjob_info* job)
{
    struct queue_item *q_item = kmalloc(sizeof(struct queue_item), GFP_KERNEL);
    struct list_head *cur;
    int j;
    if (! q_item) {
        send_errc(job->pipe, -ENOMEM);
        return ;
    }
    mutex_lock(q_mtx);

   for (j=0; j<MAX_PRIORITY;j++) {
        if (list_empty(jobs_q[j])) {
            continue;
        }
        list_for_each_safe(cur, jobs_q[j], &q_item->item) {
            if (q_item->job->jobid == job->jobid) {
                send_err(job->pipe, 0, "Job id: %d removed from queue", q_item->job->jobid);
                list_del(cur);
                break;
            }
        }
    }
    if (j==MAX_PRIORITY) {
         send_err(job->pipe, 0, "Job id: %d not found in queue", job->jobid);
    }
    mutex_unlock(q_mtx);
}

/*
 * Print Kernel Job Queue
 * - no separate thread, done by submit job
 */
void u_print_queue(struct kjob_info* job)
{
    struct queue_item *q_item;
    struct list_head *cur;
    char queue_empty_msg[25];
    int j;
    
    printk("Job Queue\n-----------------------------\n");
    mutex_lock(q_mtx);

   for (j=0; j<MAX_PRIORITY;j++) {
        if (list_empty(jobs_q[j])) {
            snprintf(queue_empty_msg, 25, "Queue %d is empty", j);
            send_info(job->pipe, queue_empty_msg);
            continue;
        }
        printk("queue %d:\n", j);
        list_for_each(cur, jobs_q[j]) {
            q_item = list_entry(cur, struct queue_item, item);
            send_err(job->pipe, 0, "Job id: %d", q_item->job->jobid);
            switch(q_item->job->optype) {
            case OP_CHECKSUM:
                send_info(job->pipe, "Operation type: CHECKSUM \n");
                break;
            case OP_CRYPT:
                send_info(job->pipe, "Operation type: CRYPT \n");
                break;
            case OP_CONCAT:
                send_info(job->pipe, "Operation type: CONCAT \n");
                break;
            case OP_COMPRESS:
                send_info(job->pipe, "Operation type: COMPRESS \n");
                break;
            }
            
        }
    }
    mutex_unlock(q_mtx);
}

    
static int process_job(struct kjob_info* job) {
    int rc = 0;
    /* may be replace with switch case statement later */
    switch(job->optype) {
    case OP_CHECKSUM:
        printk("calling checksum\n");
        rc = get_checksum(job);
        if(rc < 0){
            send_errc(job->pipe, rc);
        }
        return rc;
    case OP_CONCAT:
        printk("calling concat\n");
        rc = concat_files(job);
        if(rc < 0){
            send_errc(job->pipe, rc);
        }
        return rc;
    case OP_COMPRESS:
        printk("calling compress\n");
        send_info(job->pipe, "it's compress\n");
        rc = hw3_compress(job);
        if(rc < 0){
            send_errc(job->pipe, rc);
        }
        return rc;
    case OP_CRYPT:
        printk("calling cryption \n");
        send_info(job->pipe, "it's cryption \n");
        rc = hw3_encrypt(job);
        if(rc < 0){
            send_errc(job->pipe, rc);
        }
        return rc;
    default:
        printk("Bad optype:%d\n", job->optype);
        return -EINVAL;
    }
    return rc;
}

/*
 * consumer thread function
 *
 * schedule() when there is no more task to do
 *
 * Avoid lost wake-up problem: set task status to TASK_INTERRUPTIBLE before checking job list
 *  corner case: what if this thread gets suspended right before schedule()
 is called now, and a new item is  inserted by producer thread?
 *  - this is not a problem anymore: if scheduler puts the consumer thread to sleep
 at mentioned point:  the thread's
 *   status is already TASK_INTERRUPTIBLE, it sure will catch the event and wake up
 *
 * in case of the else block: set status back to TASK_RUNNING. Why?
 *  Consumer thread needs to receive wake up events only when there is real necessity
 (job comes during sleep)
 *  reaching the else blcok means we already have job/s in queue. Keeping thread on status
 TASK_INTERRUPTIBLE
 *  is waste of CPU making it check for events
 *
 * right after schedule(): set status back to TASK_RUNNING. Why?
 *  This wake up means a job has been added by producer. It is a good time to set status
 back to running which helps
 *  stay consistent with the next call of kthread_should_stop()
 */
static int consumer_threadfn(void *data) {
    struct queue_item *q_item = NULL;
    /*0=not running, 1=running. Use the flag to let producer/main thread know
      if this consumer is running*/
    int *state = (int *)data;
    int rc = 0;
    int i=0;

    printk("\tconsumer thread inited with address %d\n", (int) state);
    
    while (!kthread_should_stop()) {
        set_current_state(TASK_INTERRUPTIBLE);
        mutex_lock(q_mtx);

        if (jobs_num == 0) {
            printk("\tcons: jobs=%d, going sleep...\n", jobs_num);            
            mutex_unlock(q_mtx);

            *state = 0;
            
            schedule();
            *state = 1;
            set_current_state(TASK_RUNNING);
        } else {
            *state = 1; /*set it just in case*/
            /* mark state as running as job might not had been scheduled
               and status is still TASK_INTERRUPTIBLE */
            set_current_state(TASK_RUNNING);
            
            /* here we're going to pick a job from the head of the queue.
             * multi-queues: think of it as the queue we are picking the job from
             * when first queue is empty go to next one and so on..
             */
            i=0; while(list_empty(jobs_q[i]) && ++i<MAX_PRIORITY);   /* starts from queue 0, 1 ans so on.. */
            if (i>=MAX_PRIORITY) {
                printk("WARNING: no items in queue, but jobs_num=%d.Resetting it\n",
                       jobs_num);
                jobs_num = 0;
                mutex_unlock(q_mtx);
                continue;
            }

            print_queue();

            /* there are jobs to execute, pick from head and decrment the counter */
            --jobs_num;
            
            q_item = list_first_entry(jobs_q[i], struct queue_item, item);
            list_del(jobs_q[i]->next);
            
            printk("\tcons: doing operation type %d (jobs num:%d)...",
                   q_item->job->optype, jobs_num+1);
            
            mutex_unlock(q_mtx);

            if ((rc = process_job(q_item->job)) < 0)
                printk("Error when processing a job: %d\n", rc);

            printk("job finished %d\n", rc);
            /* tell user it's finished */
            terminate_msg(q_item->job->pipe);
            
            kfree(q_item->job); /* TODO: where do we deallocate job->opt ? */
            kfree(q_item);
        }
    }

    printk("%s consumer thread exits.\n", __FUNCTION__);
    return 0;
}

/* Calls the appropr. function to copy custom options. Clear source options. */
static int kcopy_jobinfo(struct kjob_info *dst, struct kjob_info *src) {
    int rc = 0;
    if (!dst) {
        printk("null dst\n");
        rc = -EINVAL;
        goto errout;
    }
    if (!src->filename || !src->outfilename || !src->opts) {
        printk("Null src args, opts=%d\n", (int)src->opts);
        rc = -EINVAL;
        goto errout;
    }
    memset(dst, 0, sizeof(struct kjob_info)); /* error scenarios */
    dst->optype = src->optype;
    dst->pipe = src->pipe;
    dst->pipefd = src->pipefd;
    dst->priority = src->priority;

    /*
     * TODO:
     *  Ensure consumer is properly deallocating file names
     */        
    if (!(dst->filename = kstrdup(src->filename, GFP_KERNEL))) {
        rc = -ENOMEM;
        goto errout;
    }
    
    if (!(dst->outfilename = kstrdup(src->outfilename, GFP_KERNEL))) {
        rc = -ENOMEM;
        goto errout;
    }
    
    switch(src->optype) {
    case OP_CHECKSUM:
        rc = kcopy_checksum_info(dst, src);
        break;
    case OP_CONCAT:
        rc = kcopy_concat_info(dst, src);
        break;
    case OP_COMPRESS:
        rc = kcopy_compress_info(dst, src);
        break;
    case OP_CRYPT:
        rc = kcopy_encrypt_info(dst, src);
        break;
    default:
        printk("Unrecognized operation type:%d\n", src->optype);
        rc = -EINVAL;
        goto errout;
    }

 errout:
    /* TODO:
     * On ERROR:
     *  do we properly free source pointer members properly?
     */

    if (rc) {
        printk("free in copy\n");
        if (dst->filename)
            kfree(dst->filename);
        if (dst->outfilename)
            kfree(dst->outfilename);
    }
    printk("free src in copy\n");
    if (src->opts) {
        kfree(src->opts);
        src->opts = NULL;
    }
    //to tell producer that current op should be skipped
    src->optype = -1;

    return rc;
}

/* returns index of the first available consumer, or -1 if none */
static int select_next_consumer(void) {
    int i=0;
    for(i = 0;i < CONSUMERS_NUM;++i) {
        if (!consumers_state[i]) {
            return i;
        }
    }
    return -1;
}

/*
 * producer thread function
 * if there was no job before and a job has just been added
 *  wake up the consumer, use - wake_up_process()
 *
 * TODO: Replace Goto if there is no memory allocation ordering here
 */
static int producer_threadfn(void *job_data) {
    struct kjob_info *kjob = (struct kjob_info*) job_data;
    struct queue_item *q_item;
    int rc = 0, next_consumer_index;

    while (!kthread_should_stop()) {
        mutex_lock(q_mtx);
        if (kjob->optype == -1) {
            mutex_unlock(q_mtx);
            /* should we lock u_mtx again after continue? */
            mutex_unlock(u_mtx);            
            printk("sleep & skip\n");
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();
            continue;
        }
        printk("prod: NEW TASK TYPE %d (jobs: %d)\n", kjob->optype, jobs_num);

        jobs_num++;

        /* append the job to the tail of the queue */
        if (!(q_item = kmalloc(sizeof(struct queue_item), GFP_KERNEL))) {
            send_errc(kjob->pipe, -ENOMEM);
            goto free_sleep;
        }

        /* copy to the queue item job by value from the area of memory
           which producer_data points to */
        if (!(q_item->job = kzalloc(sizeof(struct queue_item), GFP_KERNEL))) {
            send_errc(kjob->pipe, -ENOMEM);
            goto free_sleep;
        }

        if ((rc = kcopy_jobinfo(q_item->job, kjob))) {
            send_errc(kjob->pipe, rc);
            goto free_sleep;
        }
        
        q_item->job->jobid = g_jobid++;
        /* take care of overflow */
        if (g_jobid > 0)
            g_jobid = 1;

        goto donext;
    free_sleep:
        terminate_msg(kjob->pipe);
        fput(kjob->pipe);
            
        mutex_unlock(q_mtx);
        mutex_unlock(u_mtx);
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
        continue;

    donext:
        /* adding to the queue */
        INIT_LIST_HEAD(&q_item->item);
        /* ensure valid priority */
        printk("producer received priority: %d\n", q_item->job->priority);
        if (q_item->job->priority > 0 && q_item->job->priority <= MAX_PRIORITY)
            list_add_tail(&q_item->item, jobs_q[q_item->job->priority-1]);
        else
             send_err(kjob->pipe, -EINVAL, "Unexpected priority");
        
        mutex_unlock(u_mtx);
        
        next_consumer_index = select_next_consumer();
        /* make a decision which consumer thread to wake up.
           if all of them are running - they'll pick the job from the queue later */
        if (next_consumer_index != -1) {
            printk("prod: awaken consumer index %d\n", next_consumer_index);
            send_info(kjob->pipe, "I assigned you to a consumer\n");

            /* fput the pipe so that consumer could use it */
            wake_up_process(consumers[next_consumer_index]);
        }        
        
        mutex_unlock(q_mtx);
        /* no more work to do, sleeping is a good idea */
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
    printk("%s producer thread exits.\n", __FUNCTION__);
    return 0;
}

/*
 * Initialize consumer thread
 * Initialize producer thread
 *  We create threads but they are not put into scheduler's queue
 *  so they are sleeping
 */
int __init hw3_init_kthread(void) {
    int rc = 0, i;
    struct task_struct *consumer_thread;
    printk("init threads\n");
    /* initialize data for producer thread */
    if (!(producer_data = kmalloc(sizeof(struct kjob_info), GFP_KERNEL))) {
        rc = -ENOMEM;
        goto errout;
    }
    producer_data->filename = producer_data->outfilename = NULL;
    
    /* an indicator that job has not been set by pass_job yet */
    producer_data->optype = -1;
    
    /* this pointer is allocated only once and used as a temp.buffer
    for all incoming user requests. Since ->opts will point to different
    operation options, let's allocate memory for the largest structure we have
    
    Atiq: don't allocate this here, set it to NULL    
    */
    producer_data->opts = NULL;

    /* init consumers. assign state to consumers to check if they're running in the future */
    if (!(consumers_state = kmalloc(CONSUMERS_NUM * sizeof(int), GFP_KERNEL))) {
        return -ENOMEM;
    }
    consumers = kmalloc(CONSUMERS_NUM * sizeof(struct task_struct *), GFP_KERNEL);
    if (!consumers) {
        return -ENOMEM;
    }
    for (i = 0; i < CONSUMERS_NUM; ++i) {
        consumers_state[i] = 0;
        consumer_thread = kthread_create(&consumer_threadfn, &consumers_state[i],
                                         "consumer-thread %d", i + 1);

        if (IS_ERR(consumer_thread)) {
            rc = PTR_ERR(consumer_thread);
            printk(KERN_ERR "%s: Failed to create consumer thread; rc = [%d]\n",
                   __func__, rc);
            return rc;
        }
        consumers[i] = consumer_thread;
    }    

    /* create producer thread */
    producer_kthread = kthread_create(&producer_threadfn, (void *) producer_data,
                                      "producer-kthread");
    if (IS_ERR(producer_kthread)) {
        rc = PTR_ERR(producer_kthread);
        printk(KERN_ERR "%s: Failed to create kernel thread; rc = [%d]\n", __func__, rc);
        return rc;
    }

    /* init the jobs queue */
    for (i=0; i<MAX_PRIORITY; i++) {
        if (!(jobs_q[i] = kmalloc(sizeof(struct list_head), GFP_KERNEL))) {
            rc = -ENOMEM;
            goto q_free;
        }
        INIT_LIST_HEAD(jobs_q[i]);
    }

    /* init queue and user mutexes */
    if (!(q_mtx = kmalloc(sizeof(struct mutex), GFP_KERNEL)))
        return -ENOMEM;    
    mutex_init(q_mtx);    
    if (!(u_mtx = kmalloc(sizeof(struct mutex), GFP_KERNEL)))
        return -ENOMEM;    
    mutex_init(u_mtx);
    goto errout;

q_free:
    while(--i>=0)
       if (jobs_q[i])
          kfree(jobs_q[i]); 
errout:
    return rc;
}

/*
 * Threads should only exit when
 * kthread_stop() is called, not themselves
 */
void hw3_destroy_kthread(void) {        
    /* will throw a segmentation fault if thread already exited!
     so we check if thread is running or no */
    int i;
    for (i = 0;i < CONSUMERS_NUM; ++i) {
        if (consumers_state[i]) {
            printk("stopping consumer %d\n", i);
            kthread_stop(consumers[i]);
            consumers_state[i] = 0;
        }
    }
    kfree(consumers_state);
    kfree(consumers);
    
    if (prod_running) {
        printk("stopping producer\n");
        kthread_stop(producer_kthread);
        prod_running = 0;
    }

    if (producer_data) {
        /* all members are free inside the producer routine */
        kfree(producer_data);
    }
    if (q_mtx)
        kfree(q_mtx);
    if (u_mtx)
        kfree(u_mtx);

    for (i=0; i<MAX_PRIORITY; i++)
        if (jobs_q[i])
            kfree(jobs_q[i]);
}

