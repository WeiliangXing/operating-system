#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h> // for getopt
#include <asm/unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/md5.h>
#include "myargs.h"//myargs struct

#define __NR_xcrypt 359
#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

#define TRUE 1
#define FALSE 0
typedef unsigned char bool; // created type bool

/*
This the main function in user mode. By input requested legal arguments,
The function will first check validility of arguments at user mode; if it 
is legal, the arguments will be passed to system call to realize encryption
and decryption.
For details please refer README.md.
 */
int
main (int argc, char **argv)
{

  int rc;
  int c;

  char *keyFlag = NULL; //-p flag for key.
  char *cryptFiles[2];//in and out files
  int cryptF = 0;//flag for en/decrption: 0 for en, 1 for decrption;
  int filesIndex = 0;// for cryptFile indexing
  bool isEChecked = FALSE;
  bool isDChecked = FALSE;
  bool isPChecked = FALSE;
  bool isAllValid = TRUE;
  int keyLen; // input key length
  // unsigned int hashLen;//hash key length
  MD5_CTX digestObject;//for digest process
  unsigned char outputBuffer[MD5_DIGEST_LENGTH];//output buffer
  int i;
  int initH;
  int updateH;
  int finalH;
  char md5res[33];
  char *digest;

  //*Reference*
  //http://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
  opterr = 0;
  while ((c = getopt (argc, argv, "p:e:d:h")) != -1){
    switch (c){
      case 'p': // key password
        keyFlag = optarg;
        isPChecked = TRUE;

        break;
      case 'e'://encrption
        isEChecked = TRUE;
        optind--;
        for(; optind < argc && *argv[optind] != '-'; optind++){
        	cryptFiles[filesIndex++] = argv[optind];
        }
        break;
      case 'd'://decrption
        cryptF = 0;
        isDChecked = TRUE;
        optind--;
        for(; optind < argc && *argv[optind] != '-'; optind++){
        	cryptFiles[filesIndex++] = argv[optind];
        }
        break;
      case 'h'://helpful message
        printf("./xcipher -p <Password> -e <inputFile> <outputFile> for encryption;\n");
        printf("./xcipher -p <Password> -d <inputFile> <outputFile> for decryption.\n");
        break;
      case '?':// no arg cases
      	//case 0: no arg for -p -e -d	
        if (optopt == 'e' || optopt == 'p' || optopt == 'd'){
          fprintf(stderr, "Error: Option -%c requires an argument.\n", optopt);
        }
        else if (isprint (optopt))
          fprintf(stderr, "Error: Unknown option `-%c'.\n", optopt);
        else
          fprintf(stderr,
                   "Error: Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
      	abort();
    }//end switch
  }//end while

 	//====== Error checking=======//
 	//case 1.0 : no arguments
 	if(!isPChecked && !isDChecked && !isEChecked){
 		fprintf(stderr, "Error: no input.\n");
 		isAllValid = FALSE;
 	}
 	//case 1.1: no p
 	else if(!isPChecked){
 		fprintf(stderr, "Error: -p is not set.\n");
 		isAllValid = FALSE;
 	}
 	//case 1.2: no e or d set
 	else if(!isDChecked && !isEChecked){
 		fprintf(stderr, "Error: neither -d nor -e is not set.\n");
 		isAllValid = FALSE;
 	}
 	//case 1.3: e and d set at the same time
 	else if(isDChecked && isEChecked){
 		fprintf(stderr, "Error: -d and -e are set at the same time.\n");
 		isAllValid = FALSE;
 	}
 	//case 2: -p's passwords should be at least 6 chars long
 	else if(strlen(keyFlag) < 6){
 		fprintf(stderr, "Error: length of -p arg is %i which is less than min(6).\n", strlen(keyFlag));
 		isAllValid = FALSE;
 	}
 	//case 3: in and out file should has args
 	else if(cryptFiles[1] == NULL){
 		fprintf(stderr, "Error: lack output filename.\n");
 		isAllValid = FALSE;
 	}
 	else{
 		isAllValid = TRUE;
 	}

 	if(!isAllValid){
 		printf("%s\n", "The input is not valid");
 		return 1;
 	}
 	//======Post-error-checking====//
 	//input satisfy basic requirement, however, deep check will be in kernel
  // *Note* From here, at user level, all input has something
 	// set 1: set flag = 0 for decrption, 1 for encrption.
 	if(isDChecked && !isEChecked)
 		cryptF = 0;
 	if(!isDChecked && isEChecked)
 		cryptF = 1;
 	
  // printf("passwd is: %s, type is %i, inputFile is %s, outputFile is %s\n",
  //         keyFlag, cryptF, cryptFiles[0], cryptFiles[1]);

  //====== Generate Hash using MD5======//

  keyLen = strlen(keyFlag);
  initH = MD5_Init (&digestObject);
  updateH = MD5_Update (&digestObject, keyFlag, keyLen);
  finalH =MD5_Final (outputBuffer,&digestObject);

  //trick: To maintain key size 16, build a larger
  //char array and trim the first 16 chars.
  for(i = 0; i < 16; i++)
    sprintf(&md5res[i*2], "%02x", outputBuffer[i]);
  digest = malloc(16*sizeof(char));;
  for(i = 0; i < 16; i++)
    digest[i] = md5res[i];
  // printf("hashed key is: %s\n", digest);

  //======Build myargs struct for kernel=====/

  myargs m, *mptr = &m;
  mptr->passwdBuf = digest;
  mptr->passwdLen = MD5_DIGEST_LENGTH;
  mptr->inFile = cryptFiles[0];
  mptr->outFile = cryptFiles[1];
  mptr->flag = cryptF;
  // printf("got password: %s\n", keyFlag);
  // printf("got hash: %s\n", (char *)mptr->passwdBuf);
  // printf("len of MD5: %i\n", mptr->passwdLen);
  // printf("got password: %s\n", mptr->passwdBuf);

  //begin system call for encryption and decryption
  rc = syscall(__NR_xcrypt, mptr);

  //========Return Errno or succeed========//

  if (rc == 0){ // succeed finish work
    if(cryptF == 1)
      printf("Encrption works! syscall returned %d\n", rc);
    else
      printf("Decrption works! syscall returned %d\n", rc);

  }
  else{
    if(cryptF == 1)
      printf("Encrption fails! ");
    else
      printf("Decrption fails! ");
    printf("syscall returned %d (errno=%d)\n", rc, errno);
    switch(errno){
      case EFAULT:
        printf("Bad Address.\n");
        break;
      case EINVAL:
        printf("Invalid arguments.\n");
        break;
      case ENAMETOOLONG:
        printf("Input/output filename is too long.\n");
        break;
      case EPERM:
        printf("(Read/Write/Open/Encrption/Decrption,etc)Operation not permitted/Wrong key used.\n");
        break;
      case ENOMEM:
        printf("There is not enough memory.\n");
        break;
      case ENOENT:
        printf("There is no such file/file open errors\n");
        break;
      case EISDIR:
        printf("The input/output file is not regular\n");
        break;
      case EKEYREJECTED:
        printf("The key for decrption is not valid\n");
        break;
      case ESPIPE:
        printf("Encrption process has problems\n");
        break;
      default:
        printf("The error is unregular.\n");
        break;
    }
  }

  exit(rc);
}

