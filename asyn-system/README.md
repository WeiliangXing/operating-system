#This is the operating project to build an asynchronized module .

###Abstraction
The project implements producer-consumer model to handle I/O heavy operations 

###Asynchronize mechanism
When receiving a call from the client, our implemented system call in the kernel first validates the arguments which includes testing for null pointers to avoid future null dereferencing in the kernel. Then it needs to copy data to a producer.
When kernel module is built and cleaned we take advantage of 2 hook functions: init_sys_submitjob and exit_sys_submitjob.
Both of them are defined in thread.c file. The function init_sys_submitjob creates a producer thread, and multiple consumer threads. The main goal of producer thread is to feed data to consumer threads using a queue. When creating a producer, we pass struct kjob_info *producer_data as an argument to the producer thread routine. This variable is a static variable, and serves as a temporary buffer used when we copy user job to producer, because, during submission, we copy from userland to producer_data variable, while producer is sleeping and then we wake it up, and producer uses it to copy next data from this shared variable to the new variable which next will be appended to the queue. In order to achieve consistency here, we protect producer_data with u_mtx (user mutex). When job is submitted, we open a u_mtx before getting hold of the producer_data, and the awake the producer thread, which, if no validation and other errors happened, release this lock after copying the data from producer_data to the queue item.
We decided to use a single producer thread because all what it does is takes a lock, allocates a new item for queue, appends it to the queue, wakes up available consumer. This will never take long so using multiple producers, in our opinion, would be an overkill for the system.

When there are no submissions, producer thread sleeps. When a user submits a job, producer wakes up and and picks up the job in the producer_data variable. Then it has to pass this job to consumer by appending it to the queue. Regarding consumer threads, they sleep unless there’s something to process. After putting a job into the queue, producer wakes a consumer up if the queue was empty. It uses a simple algorithm ­ pick the first who is not running. If all consumers are running ­ it doesn’t have to do anything (goes to sleep so that next user request would wake it up). Then consumer looks in the queue, if it contains at least 1 element, it processes it, if no it goes to sleep.
There are 2 situations when we need to know if a consumer is running or no:
­ when the producer needs to wake up a consumer for this job
­ when unloading the syscall module, we stopping kthreads only if they’re running.
To maintain consumer state we use an array of flags called consumers_state. When creating each of consumer threads, we pass the address of each item so that consumer could reliably report about their status. Since this array gets accessed and modified from different threads (main kernel thread, producer, consumers) it’s protected by q_mtx mutex.

### Key files
- sys_submitjob.c : puts the job in proper place for processing
- thread.c : Producer and consumer thread routines; thread management
- thread.h : file with thread function declarations
- utils.c  : General utilities and messaging functions (initialize pipe, send info, error, etc.) 
- utils.h : declarations for utilities

### NOTE
Other files are mainly about feature implementation. key files list above are key parts of producer-consumer implementation.
