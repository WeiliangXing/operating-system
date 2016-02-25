/*
 *  Initialization and destroy functions are here
 */
#ifndef HW3_KERNEL_H
#define HW3_KERNEL_H

#include "common.h"

/* the purpose of this structure is to link job and
   its posititon in a queue. */
struct queue_item {
    struct kjob_info *job;
    struct list_head item; /* queue support */
};

int __init hw3_init_kthread(void);
void hw3_destroy_kthread(void);
void wake_up_producer(void);
struct kjob_info *get_producer_data(void);
void unlock_user_mtx(void);
void u_print_queue(struct kjob_info* job);
void remove_job_from_queue(struct kjob_info* job);

#define CONSUMERS_NUM    2
#endif
