/*
 * this header file is shared with user space
 *  don't declare kernel headers
 *  don't declare anything that is not useful on the kernel side
 *  things that are only important on user side declare in demo_u.h
 */

#ifndef _HW_SHARED_COMMON_H
#define _HW_SHARED_COMMON_H

/*limit length of target string*/
#define MAX_STR         100

/*limit length of index array*/
#define MAX_OCC         100
#define MAX_MSG_LEN     128
/* ->type of struct k_msg */
#define MSG_FINISH      1
#define MSG_ERROR       2
#define MSG_HASDESC     4
#define MAX_PRIORITY    4

/* msg for pipe. kernel tells user what happened*/
struct k_msg {
    int type;
    /*if type is MSG_ERROR, errcode is set to something,
      e.g. EINVAL*/
    int errcode;
    char desc[MAX_MSG_LEN];
};

/*
 * represent command line arguments
 */
struct kjob_info {
    /* file name to process */
    char *filename;
    char *outfilename; /* for now*/
    /* operation type is type of task (checksum, etc) */
    int optype;
    /* operation options. depending on the operation may be */
    /* generic pointer to any kind of operation options */
    void *opts;
    
    /* file desc. for pipe. For user buffer it'll correspond
       to the read end of the pipe, for the kernel one -
       write end.
       Kernel (main thread) is responsible for setting it
       up for both user and kernel.*/
    int pipefd;

    /*keep pipe here so that this struct can be used in kernel
     in different threads without need to open a new pipe*/
    struct file *pipe;
    int priority;
    int jobid;
};


/*
 * Structures for str operations
 */
struct strops_args{
    int flag; /* 0 for search, 1 for delete, 2 for replace */
    char *in_file; /*input_file */
    int old_len;/*len of target string*/
    char *old_str; /* target string */
    int new_len;/*len of new string */
    char *new_str;/*len of new strng*/
    int res_len; /* len of res array*/
    long res[100];/* int array for indexes of all occurrences */
};

/*checksum argument struct*/
struct checksum_args {
    char *alg;
    char checksum[33];
};

/*concatenation argument struct*/
struct concat_args {
    int inf_num;    /* number of input files: 1 less because first one is in
                       jobinfo structure */
    char **in_files;/* input_files, unlimited number of file args supported,
                                        modification by Atiq */
};

/*compress argument struct*/
struct compress_args {
  /* COMPRESS or DECOMPRESS */
  int op;        
  /* Rename original file */
  int rename;

  /* options provided by include/linux/zlib.h */
  int zlib_compression_level;
  int zlib_method;
  int zlib_window_bits;
  int zlib_mem_level;
  int zlib_strategy;
};

/*encryption argument struct*/
struct encrypt_args {
  int op;
  char *key;
  int cipher_type;
};


#define DO_COMPRESS 1
#define DO_DECOMPRESS 2
#define DO_ENCRYPT 1
#define DO_DECRYPT 2

/* operation types - use enum instead of define, no need to remember numbers for adding a new one */
enum CMD_Ops{
    OP_CHECKSUM,        /* start from 0 to ensure OPTYPE_SET works as the
optype is set to -1, and macro tests if jobtype is already set */
    OP_CONCAT,
    OP_COMPRESS,
    OP_CRYPT,
    OP_LIST_JOBS,
    OP_HELP /* special type for user */
};

#endif /* _HW_SHARED_COMMON_H */
