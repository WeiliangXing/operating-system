/*
 * Implements main function for the user program and implements other functions
 * mentioned in header
 *
 */

#include "demo.h"
/* for aio */
#include <sys/types.h>
#include <aio.h>
#include <fcntl.h>

#define MAX_BUF 1024

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

static int msgsz;

/*shows the response from server. if server terminated, returns 1 to exit*/
static int show_response_and_exit(struct k_msg msg, int msglen) {
    if (msglen == msgsz) {
        if (msg.type & MSG_FINISH) {
            puts("Finished");
            return 1;
        } else if (msg.type & MSG_ERROR) {
            if (msg.type & MSG_HASDESC)
                printf("Error: %s (%s, code=%d)\n", msg.desc, strerror(-msg.errcode),
                       msg.errcode);
            else
                printf("Error: %s, code=%d\n", strerror(-msg.errcode), msg.errcode);
        } else if (msg.type & MSG_HASDESC)
            printf("%s\n", msg.desc);        
    } else
        printf("Received part of message %d/%d bytes\n", msglen, msgsz);    

    memset(&msg, 0, msglen);
    return 0;
}

/*function to read test_cases filef for testing and demo*/
int read_file(char *dir, char **reads){
    FILE *file;
    // char *line = malloc(128);
    char line[MAX_BUF];
    int rc = 0;
    int count = 0;
    static int lineNumber = 0;

    file = fopen(dir, "r");
    if(file == NULL){
        printf("%s\n", "Fail to read test file!");
        rc = -EFAULT;
        return rc;
    }
    while(fgets(line, MAX_BUF, file) != NULL){
        if(count == lineNumber){
            lineNumber++;
            *reads = strdup(line);
            *reads[strlen(line)-1] = 0;
            // line[strlen(line) - 1] = '\0';
            // strcpy(reads, line);
            break;
        }else
        count++;
    }
    if(fgets(line, 128, file) == NULL){
        lineNumber = 0;
        printf("Reach End of file! start over again.\n");
    }
    fclose(file);
    free(line);
    return rc;
}

/*main function in user side*/
int main(int argc, char* argv[]) {
    int rc = 0, i = 1;
    pthread_t tid[100];
    
    char inputbuf[MAX_BUF];
    char *tdbuf;

    memset(inputbuf, 0, MAX_BUF);
    while(i<=100 && fgets(inputbuf, MAX_BUF, stdin)) {
        tdbuf = strdup(inputbuf);
        tdbuf[strlen(inputbuf)-1] = 0;

        if (!strcmp("exit", tdbuf))
            break;

        if(!strcmp("test", tdbuf)){
            char *test_input;
            FILE *file;
            char line[MAX_BUF];
            int count = 0;
            static int lineNumber = 0;

            file = fopen("test_cases.txt", "r");
            if(file == NULL){
                printf("%s\n", "Fail to read test file!");
                rc = -EFAULT;
            }
            while(fgets(line, MAX_BUF, file) != NULL){
                if(count == lineNumber){
                    lineNumber++;
                    test_input = strdup(line);
                    test_input[strlen(line)-1] = 0;
                    break;
                }else
                count++;
            }
            if(fgets(line, MAX_BUF, file) == NULL){
                lineNumber = 0;
                printf("Reach End of file! start over again.\n");
            }
            fclose(file);
            if(rc < 0)
                printf("Cannot run tests!\n");
            else{
                printf("%s\n", test_input);
                if ((rc = pthread_create(&tid[i], NULL, &do_syscall, (void *)test_input))) 
                    printf("\ncan't create thread :[%s]", strerror(rc));  
            }

        } else {
            if ((rc = pthread_create(&tid[i], NULL, &do_syscall, (void *)tdbuf))) 
                printf("\ncan't create thread :[%s]", strerror(rc));
        }

        memset(inputbuf, 0, MAX_BUF);
        i++;
    }

    printf("Exit program\n");
    return rc;    
}

/*make system call for inputs*/
void *do_syscall(void *rawinput) {
    int argc;
    char **argv = NULL;
    struct kjob_info* jobinfo = NULL;
    int rc = 0, i;
    int numBytes = 0; /* msglen; */
    wordexp_t we;
    struct aiocb cb;   /* aio */

    /*reading fd to get async msgs from kernel*/
    int readfd = 0;
    struct k_msg msg;    

    if (strlen((char *)rawinput) == 0) {
        printf("can't have 0 args\n");
        return NULL;
    }
    msgsz = (int) sizeof(struct k_msg); /* to save on getting size of this struct */

    /* parsing input thread data to build an array of
     arguments as if it came from main function of a program*/
    if (wordexp((char *)rawinput, &we, 0)) {
        printf("Invalid input\n");
        goto very_out;
    }

    argc = we.we_wordc + 1;
    if (!(argv = malloc(argc * sizeof(char *)))) {
        printf("No memory\n");
        goto out;
    }
    /*zero the pointers out to check on NULL when freeing.*/
    memset(argv, 0, argc * sizeof(char *));
    if (!(argv[0] = strdup("demo"))) {
        printf("No memory\n");
        goto out;
    }
    for (i = 1;i < argc;++i) {
        if (!(argv[i] = strdup(we.we_wordv[i - 1]))) {
            printf("No memory\n");
            goto out;
        }
    }

    /* build a job: structure to be sent to the kernel */
    if (!(jobinfo = malloc(sizeof(struct kjob_info)))) {
        printf("Not enough memory!\n");
        rc = -ENOMEM;
        goto out;
    }
    memset(jobinfo, 0, sizeof(struct kjob_info));

    /* indicator that operation type not set */
    jobinfo->optype = -1;   
    if ((rc = parse_opts(argc, argv, jobinfo))) {
        printf("Einval \n");
        rc = -EINVAL;
        goto out;
    }
    if (jobinfo->optype == OP_HELP) {
        rc = 0;
        goto out;
    }
    print_opts(jobinfo);

    rc = syscall(__NR_submitjob, jobinfo);
    if (rc == 0) {
        readfd = jobinfo->pipefd;
        printf("reading from fd %d\n", readfd);
        memset(&cb, 0, sizeof(struct aiocb));
        cb.aio_nbytes = msgsz;
        cb.aio_fildes = readfd;
        cb.aio_offset = 0;
        cb.aio_buf = &msg;
        do {
            if (aio_read(&cb) == -1)
            {
                puts("Unable to create request!");
            }


            while(aio_error(&cb) == EINPROGRESS)
            {
                /* do something useful:
                 * increment PI or print something
                 printf(".");
                 or may be print a large fibonacci each time just for fun!
                 */
            }

            numBytes = aio_return(&cb);
            if (numBytes != -1) {
                show_response_and_exit(msg, numBytes);
            }
            else
                puts("Error!");
        } while(numBytes > 0);
    }
    else {
        printf("syscall returned %d (errno=%d)\n", rc, errno);
        perror("Detail of the error");
    }

    /* We need to free up the allocated resources here too */
 out: 
    i = 0;
    
    if (jobinfo) {
        if (jobinfo->filename)
            free(jobinfo->filename);
        if (jobinfo->outfilename)
            free(jobinfo->outfilename);
        if (jobinfo->optype == OP_CONCAT && ((struct concat_args *)jobinfo->opts)->in_files) {
            for (i=0; i < ((struct concat_args *)jobinfo->opts)->inf_num; i++)
                free(((struct concat_args *)jobinfo->opts)->in_files[i]);
            if (i)
                free(((struct concat_args *)jobinfo->opts)->in_files);
        }
        if (jobinfo->opts)
            free(jobinfo->opts);
        free(jobinfo);
    }
    
    wordfree(&we);
    if (argv) {
        for (i = 0;i < argc; i++) 
            free(argv[i]);
        free(argv);        
    }
 very_out:
    free(rawinput);

    if (!rc) {
        printf("Finished successfully\n");
    }
    return NULL;
}

/*
 * SET ENOMEM when memory allocation fails,
 * In other error cases, return EINVAL
 */
int parse_opts(int argc, char *argv[], struct kjob_info *jobinfo) {
    int choice, rc = 0;
    const char* OTHER_OPS_EXIST = "Can't set operation since an operation is already set!\n";
    struct checksum_args *chksum_opts;
    struct concat_args *concat_opts = NULL;
    struct compress_args *compress_opts = NULL;
    struct encrypt_args *encrypt_opts = NULL;
    const char     *short_opt = "cnm:s:ha:p:i:o:k:lj:";
    struct option   long_opt[] =
    {
        {"checksum",       no_argument, NULL, 'c'},
        {"concat",      no_argument,       NULL, 'n'},
        {"crypt",      required_argument,       NULL, 'r'},
        {"compress",      required_argument,       NULL, 'm'},
        {"strop",      required_argument,       NULL, 's'},
        {"help",        no_argument,        NULL, 'h'},
        {"algorithm",     required_argument, NULL, 'a'},
        {"priority",     required_argument, NULL, 'p'},
        {"input",     required_argument, NULL, 'i'},
        {"output",     required_argument, NULL, 'o'},
        {"key",     required_argument, NULL, 'k'},
        {"list-job",     no_argument, NULL, 'l'},
        {"remove-job",     required_argument, NULL, 'j'},
        {NULL,            0,                NULL, 0  }
    };
    int infind = 0; /* last input file index for concat */
    int i = 0;
    int inf_arg_provided = 0;
    int outf_arg_provided = 0;
    int pr_arg_provided = 0;
    optind = 0;
    opterr = 0; /* instead of setting it to zero we could use this for error */
    while((choice = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1) {
        switch(choice) {
        case 0:        /* long options toggles */
            break;
        case 'h': /* Memory leak if other options specified first and this one is added last
            therefore set return value and exit with goto
        */
            printf("Operations are:\n" 
                "\t./demo                                                   \tStart the program\n"
                "\texit                                                     \tTerminate the program\n"
                "\t[-h|--help]                                              \tHelper messages\n"
                "\t[-n|--concat] -i f1..fn -o ofile -p n1                   \tConcatenate input files f1 f2...fn into\n" 
                "\t                                                         \toutput file ofile with priority n1\n"
                "\t[-c|--checksum] -i f1 -o ofile -p n1 -a alg1             \tCompute checksum of an input file f1 with\n"
                "\t                                                         \tthe option to write to output file ofile \n"
                "\t                                                         \twith priority n1 with algorithm alg1. The\n"
                "\t                                                         \tlegal algorithms are \"sha1\" and \"md5\"\n"
                "\t[-m|--compress] [-z|-x] -i f1 -o ofile -p n1             \tCompress(z)/Decompress(x) an input file \n"
                "\t                                                         \tinto output file ofile with priority n1\n"
                "\t[-r|--crypt] [-e|-d] -i f1 -o ofile -p n1 -a aes -k key1 \tEncrypt(e)/Decrypt(d) wiht input file f1, output file ofile\n"
                "\t                                                         \tkey key1, algorithm \"aes\" or \"blowfish\", and priority n1. \n" 
                "\t[-l|--list-job]                                          \tlist all queues.\n"            
                );

            jobinfo->optype = OP_HELP;
            if (optind < 3) /* h is first arg, we are good */
                return 0;
            /* not changing error value, let it handle the error(if there is one) as it is */
            goto errout;  /* will free up if previous arguments allocated memory */
        case 'c':   /* command - checksum */
            if (OPTYPE_SET(jobinfo->optype)) {
                printf(OTHER_OPS_EXIST);
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            jobinfo->optype = OP_CHECKSUM;
            if (!(jobinfo->opts = malloc(sizeof(struct checksum_args)))) {
                fprintf(stderr, "No memory\n");
                if (rc >= 0)
                    rc = -ENOMEM;
                 goto errout;
            }
            memset(jobinfo->opts, 0, sizeof(struct checksum_args));
            break;

       case 'n':   /* command - concat */
            if (OPTYPE_SET(jobinfo->optype)) {
                printf(OTHER_OPS_EXIST);
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            
            jobinfo->optype = OP_CONCAT;
            if (!(jobinfo->opts = malloc(sizeof(struct concat_args)))) {
                fprintf(stderr, "No memory\n");
                if (rc >= 0)
                    rc = -ENOMEM;
                goto errout;
            }
            concat_opts = (struct concat_args *) jobinfo->opts;
            memset(concat_opts, 0, sizeof(struct concat_args));
            break;
        
        case 'm': /* command - compress */ 
            if (OPTYPE_SET(jobinfo->optype)) {
                printf(OTHER_OPS_EXIST);
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (!optarg || !strlen(optarg) || (strcmp(optarg, "-z") && strcmp(optarg, "-x"))) {
                fprintf(stderr, "Please provide comp/decomp option.\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            jobinfo->optype = OP_COMPRESS;
            if (!(jobinfo->opts = malloc(sizeof(struct compress_args)))) {
                if (rc >= 0) rc = -ENOMEM;
                 goto errout;
            }
            memset(jobinfo->opts, 0, sizeof(struct compress_args));
            compress_opts = (struct compress_args *)jobinfo->opts;
            if (!strcmp(optarg, "-z"))
                compress_opts->op = DO_COMPRESS;
            else if (!strcmp(optarg, "-x"))
                compress_opts->op = DO_DECOMPRESS;
            else {
                puts("invalid compress args");
                goto errout;
            }
          break;

        case 'r':   /* command - crypt */
            if (OPTYPE_SET(jobinfo->optype)) {
                printf(OTHER_OPS_EXIST);
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (!optarg || !strlen(optarg) || (strcmp(optarg, "-d") && strcmp(optarg, "-e"))) {
                fprintf(stderr, "Please provide enc/dec option.\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
           
            jobinfo->optype = OP_CRYPT;
            if (!(jobinfo->opts = malloc(sizeof(struct encrypt_args)))) {
                fprintf(stderr, "No memory\n");
                if (rc >= 0)
                    rc = -ENOMEM;
                goto errout;
            }
            encrypt_opts = (struct encrypt_args *) jobinfo->opts;
            memset(encrypt_opts, 0, sizeof(struct encrypt_args));
            encrypt_opts->cipher_type = -1;
            if (!strcmp(optarg, "-e"))
                encrypt_opts->op = DO_ENCRYPT;
            else if (!strcmp(optarg, "-d"))
                encrypt_opts->op = DO_DECRYPT;
            else {
                puts("invalid crypt args");
                goto errout;
            }
            break;

        case 'p': /* priority is mandatory argument */
            if (jobinfo->optype == -1) { /*  a command is required - to use this
       argument, if optype is not set there is no use of argument input file */
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (!optarg || !strlen(optarg) || *optarg=='-') {
                fprintf(stderr, "Please provide priority of the job.\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (pr_arg_provided) {
                fprintf(stderr, "Ambiguous priority arguments specified!\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (!(jobinfo->priority = atoi(optarg)) || jobinfo->priority>MAX_PRIORITY) {
                 fprintf(stderr, "Invalid priority arguments specified: valid priority is (1-%d)!\n", MAX_PRIORITY);
                 if (rc >= 0)
                    rc = -EINVAL;
                 goto errout;
            }
            pr_arg_provided = 1;
            break;
 
        case 'i': /* i is required with almost every command */
            if (jobinfo->optype == -1) { /*  a command is required - to use this
       argument, if optype is not set there is no use of argument input file */
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (!optarg || !strlen(optarg) || *optarg=='-') {
                fprintf(stderr, "Please provide input filename argument(s).\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (inf_arg_provided) {
                fprintf(stderr, "Ambiguous input option specified!\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            jobinfo->filename = strdup(optarg);
            /* printf("value of optind: %d, argc: %d and the arg is: %s\n",
                        optind, argc, argv[optind]); */
            if (jobinfo->optype == OP_CONCAT) { /* copy rest input file arguments
                                first argument is copied into jobinfo struct */
                if (concat_opts == NULL) {
                    if (rc >= 0)
                        rc = -EINVAL;
                    goto errout;
                }
                /* infind - will always point to the last argument's index + 1,
                 *      the argument before which we stop copy
                 * optind - will always point to the argument where to start copy */
                for(infind = optind ; infind < argc && *argv[infind] != '-'; infind++);
                concat_opts->inf_num = infind - optind;
                if (concat_opts->inf_num < 1) {
                    fprintf(stderr, "Not enough number of input files provided!\n");
                    if (rc >= 0)
                        rc = -EINVAL;
                    goto errout;
                }
                /* printf("last ind: %d, last argument was: %s\n", infind, argv[infind]); */
                /* unlimited input file args copied here */
                if (! (concat_opts->in_files = malloc(concat_opts->inf_num * sizeof(char *)))) {
                    fprintf(stderr, "No memory\n");
                    if (rc >= 0)
                        rc = -ENOMEM;
                    goto errout;
                }
                for(i=0; optind < infind && *argv[optind] != '-'; optind++)
                    concat_opts->in_files[i++] = strdup(argv[optind]);
            }
            inf_arg_provided = 1;
           break;
        case 'o': /* o might not be required for all command */
            if (jobinfo->optype == -1) { /*  a command is required - to use this
       argument, if optype is not set there is no use of argument input file */
                 if (rc >= 0)
                    rc = -EINVAL;
                 goto errout;
            }
            if (!optarg || !strlen(optarg) || *optarg=='-') {
                fprintf(stderr, "Please provide output filename\n");
                  if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (outf_arg_provided) {
                fprintf(stderr, "Ambiguous output option specified!\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            jobinfo->outfilename = strdup(optarg);
            outf_arg_provided = 1;
            break;
        case 'a':   /* to work with command checksum  */
            if (jobinfo->optype != OP_CHECKSUM && jobinfo->optype != OP_CRYPT) {   /* consider encryption decryption
                                                                                                 algorithm types */
                fprintf(stderr, "Unknown option -a\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (!optarg || !strlen(optarg) || *optarg=='-') { /* check the argument specified */
                fprintf(stderr, "Please specify an algorithm\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }

            if (!jobinfo->opts) {
                fprintf(stderr, "Options didn't get initialized for checksum\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            switch (jobinfo->optype) {
                case OP_CHECKSUM:
                    chksum_opts = (struct checksum_args *)jobinfo->opts;
                    if (chksum_opts->alg) {
                        fprintf(stderr, "Set algorithm only once\n");
                        if (rc >= 0)
                            rc = -EINVAL;
                        goto errout;
                    }
                    chksum_opts->alg = strdup(optarg);
                    break;
                case OP_CRYPT:
                    encrypt_opts = (struct encrypt_args *)jobinfo->opts;
                    if (encrypt_opts->cipher_type != -1) {
                        fprintf(stderr, "Set algorithm only once\n");
                        if (rc >= 0)
                            rc = -EINVAL;
                        goto errout;
                    }
                    if (!strcmp(optarg, "aes"))

                        encrypt_opts->cipher_type = 3;
                    else if (!strcmp(optarg, "blowfish"))
                        encrypt_opts->cipher_type = 4;
                    else {
                        fprintf(stderr, "Invalid algo specified for crypt.\n");
                        if (rc >= 0)
                            rc = -EINVAL;
                        goto errout;
                    }
                    break;
                default:
                    fprintf(stderr, "Invalid operation for algo\n");
                    if (rc >= 0)
                        rc = -EINVAL;
                    goto errout;
            }
            break;

        case 'k':   /* mandatory for crypt */
            if (jobinfo->optype != OP_CRYPT) {
                fprintf(stderr, "Unknown option -k\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            if (!optarg || !strlen(optarg) || *optarg=='-') { /* check the argument specified */
                fprintf(stderr, "Please specify key\n");
                  if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
 
            if (!jobinfo->opts) {
                fprintf(stderr, "Options didn't get initialized for crypt\n");
                if (rc >= 0) 
                    rc = -EINVAL;
                goto errout;
            }
            encrypt_opts = (struct encrypt_args *)jobinfo->opts;
            if (encrypt_opts->key) {
                fprintf(stderr, "Set key only once\n");
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            encrypt_opts->key = strdup(optarg);
            printf("encrypt key set: %s\n", encrypt_opts->key);
            break;
        case 'l':
            if (OPTYPE_SET(jobinfo->optype)) {
                printf(OTHER_OPS_EXIST);
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            jobinfo->optype = -1;
            if (optind < 3) { /* l is first arg, we are good */
                jobinfo->optype = OP_LIST_JOBS;
                jobinfo->priority = 0;
                return 0;
            }
            goto errout;
        case 'j':
            if (OPTYPE_SET(jobinfo->optype)) {
                printf(OTHER_OPS_EXIST);
                if (rc >= 0)
                    rc = -EINVAL;
                goto errout;
            }
            jobinfo->optype = -1;
            if (optind < 4) { /* j is first arg, we are good */
                jobinfo->optype = OP_LIST_JOBS;
                 if (!(jobinfo->jobid = atoi(optarg))) {
                     fprintf(stderr, "Invalid job number provided %s.\n", optarg);
                     if (rc >= 0)
                        rc = -EINVAL;
                     goto errout;
                }
                return 0;
            }
            goto errout;
       case '?':
            if (optopt == 'c') 
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);      
            else if (isprint (optopt)){
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            }
            else 
                fprintf (stderr,  "Unknown option character `\\x%x'.\n", optopt);      
            if (rc >= 0)
                rc = -EINVAL;
            goto errout;
        default:
            fprintf(stderr, "Abort since an unknown argument has been found\n");
            if (rc >= 0)
                rc = -EINVAL;
            goto errout;
        }
    }    

    /* mandatory arguments check here */
    if (!pr_arg_provided) {
        fprintf(stderr, "Please provide priority argument.\n");
        if (rc >= 0)
            rc = -EINVAL;
        goto errout;
    }
    /* mandatory arguments 2 */
    if (!inf_arg_provided) {
        fprintf(stderr, "Please provide input filename argument(s).\n");
        if (rc >= 0)
            rc = -EINVAL;
        goto errout;
    }
    /* feature specific argument requirement tests here */
    switch(jobinfo->optype) {
        case OP_CONCAT: case OP_COMPRESS: case OP_CRYPT: /* check output */
        if (!outf_arg_provided) {
            fprintf(stderr, "Please provide output filename argument.\n");
            if (rc >= 0)
                rc = -EINVAL;
            goto errout;
        }
        break;
    case OP_CHECKSUM:   /* TODO: check alg etc arguments */
        if (!outf_arg_provided) {
            fprintf(stderr, "Please provide output filename argument.\n");
            if (rc >= 0)
                rc = -EINVAL;
            goto errout;
        }
        break;
    }
    if (rc == 0)
        return rc;

    /* free resources on error */
 errout:
    if (!OPTYPE_SET(jobinfo->optype))
        fprintf(stderr, "Required arguments have not been provided or some invalid arguments provided!\n");

    /* these are not allocated by parse_opts
     * caller is responsible to relese these
     */
    if (jobinfo->optype == OP_CONCAT && concat_opts->in_files) {
        for (i=0; i < concat_opts->inf_num; i++)
            free(concat_opts->in_files[i]);
        if (i)
            free(concat_opts->in_files);
    }
    
    jobinfo->optype = -1;   /* unsetting it if it is set since we are in an error
    useful only if some other operation uses this one afterwards */
    return -EINVAL;
}

/*print options of the job*/
void print_opts(struct kjob_info *job) { /* use for debugging */
    struct checksum_args * csopts;
    struct concat_args* concat_opts;
    int i;
    printf("Print opts:\n");
    printf("Operation type:%d, input filename=%s, output filename=%s\n", job->optype, job->filename, job->outfilename);
    if (job->optype == OP_CHECKSUM) {
        csopts = (struct checksum_args *) job->opts;
        printf("Algorithm:%s\n", csopts->alg);        
    }
    if (job->optype == OP_CONCAT) {
        concat_opts = (struct concat_args *) job->opts;
        printf("Number of input files (rest): %d\n", concat_opts->inf_num);        
        for (i=0; i < concat_opts->inf_num; i++)
            printf("%d -> %s\n", i+2, concat_opts->in_files[i]);
    }
}
