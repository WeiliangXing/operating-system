#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <asm/uaccess.h>
#include <linux/slab.h> // for kfree, kmalloc
#include <linux/fs.h> //for filp_open
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include "myargs.h"

#define PAGE 4096
#define BLOCK 16

asmlinkage extern long (*sysptr)(void *arg);
int isInputValid(void *arg);
int cryption(char *passwdBuf,int passwdLen, char *IV,
 char *inFile, char *outFile, int inFileLen, int *outFileLen, int flag);
int getLengthOfPad(char *inputBlock);

/*
xcrypt() is main function of system call. xcrypt accept struct myargs.h as
argument, check its validility, copy the struct into kernel, and try to open
/read the input/output file; any errors during such period will terminate 
System call. Then encryption/decryption will begin.
For details please refer README.md.
 */
asmlinkage long xcrypt(void *arg)
{
	myargs *ptr = (myargs *)arg;
	int rc = 0;
	myargs *kptr = NULL;// allocate memory for myargs struct
	struct file *readFilePtr = NULL;//for input file pointer.
	struct inode *inputIn = NULL;//for get inode of input file
	struct inode *outputIn = NULL;//for get inode of output file
	size_t inputInodeSize = 0;// for get size of input file
	umode_t inputInodeMode = 0;//for get mode of input file
	umode_t outputInodeMode = 0;//for get mode of output file

	struct file *writeFilePtr = NULL;//for output file pointer.
	mm_segment_t oldfs;
	char *bytes;// bytes from input filem
	int padding;//pad for block less than 16 (range is 1-16)
	char *pad = NULL;// pad array for output footprint for padding numbers.
	char *IV = NULL;// initialization vector
	int buf_len;
	int i = 0;
	int m;
	char hexList[16] = "0123456789abcdef";//hex dictionary for lookup
	char *firstChars;//for encrpytion
	char *firstBlock;//for encryption
	char ele;// for padding list
	int count;
	int len;

	char res[BLOCK];
	char key[BLOCK];
	char *in;
  struct hash_desc desc;
  struct scatterlist sg;
  struct crypto_hash *tfm;

	//check availiablity of the inputs of struture
	rc = isInputValid(ptr);
	if(rc != 0) 
		return rc;

	//=====by this line, the input could be regarded as valid=====//
	/*Stage I Open Input File*/
	//step1: try allocate memory
	kptr = (myargs *)kmalloc(sizeof(myargs), GFP_KERNEL);
	if(IS_ERR(kptr)){
		rc = -ENOMEM;
		goto no_mem_for_struct;
	}
	//step2: copy from user, 0 for success
	if(copy_from_user(kptr, ptr, sizeof(myargs))){
		rc = -EFAULT;
		goto no_mem_for_struct;
	}

	//step2: gen MD5 cyptos
	//*Reference*
	//Documentation/crypto/api-intro.txt
	//crypto/tcrypt.c
	in = kptr->passwdBuf;
	while(in[i] != '\0'){
		key[i] = in[i];
		i++;
	}
	key[i] = '\0';
	i = 0;
  sg_init_one(&sg, key, BLOCK);

  tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm)){
			rc = -PTR_ERR(tfm);
			goto no_mem_for_struct;
	}
  desc.tfm = tfm;
  desc.flags = 0;

  rc = crypto_hash_init(&desc);
  if(rc){
		rc = -EKEYREJECTED;
		goto no_mem_for_struct;
	}

  rc = crypto_hash_update(&desc, &sg, BLOCK);
  if(rc){
		rc = -EKEYREJECTED;
		goto no_mem_for_struct;
	}
  rc = crypto_hash_final(&desc, res);
  if(rc){
		rc = -EKEYREJECTED;
		goto no_mem_for_struct;
	}
	res[BLOCK] = '\0';
  crypto_free_hash(tfm);

	//step3: read input file, check correctness.
	//O_EXCL not O_RDONLY: for read validation
	readFilePtr = filp_open(kptr->inFile, O_EXCL, 0);
	if(!readFilePtr || IS_ERR(readFilePtr)){
		printk("Open input file error: %d\n", (int)PTR_ERR(readFilePtr));
		rc = -ENOENT;
		goto no_mem_for_struct; 
	}
	//step4: check whether has read permission:		
	if(!readFilePtr->f_op->read){
		printk("Read input file Permission Denied!\n");
		rc = -EPERM;
		goto close_input_file;
	}
	//step5: get input file size and check whether null
	inputIn = readFilePtr->f_path.dentry->d_inode;
	inputInodeSize = i_size_read(inputIn);
	
	//**
	// printk("input file's size is %zu\n",inputInodeSize);

	if(inputInodeSize <= 0){
		printk("Error: input file's size is %zu\n",inputInodeSize);
		rc = -EPERM;
		goto close_input_file;
	}
	//step6: check whether input file is regular
	inputInodeMode = inputIn->i_mode;
	if(S_ISREG(inputInodeMode) == 0){
		printk("Error: The file is not regular: input file.\n");
		rc = -EISDIR;
		goto close_input_file;
	}
	//=====by this line, the input could be regarded as readable=====//
	/*Stage II try open to the output file*/

	// check the avaialability of output file
	// for output file: open/create with same mode as input file
	//step1: check whether can open:			
	writeFilePtr = filp_open(kptr->outFile, O_WRONLY|O_CREAT, inputInodeMode);
	if(!writeFilePtr || IS_ERR(writeFilePtr)){
		printk("Open output file error: %d\n", (int)PTR_ERR(writeFilePtr));
		rc = -ENOENT;
		writeFilePtr = NULL;
		goto close_null_output_file;
	}
	//step2: check whether could be write
	if(!writeFilePtr->f_op->write){
		printk("Read output file Permission Denied!\n");
		rc = -EPERM;
		goto close_output_file;
	}
	//step3: check regularity of the output file
	outputIn = writeFilePtr->f_path.dentry->d_inode;
	outputInodeMode = outputIn->i_mode;
	if(S_ISREG(outputInodeMode) == 0){
		printk("Error: The file is not regular: output file.\n");
		rc = -EISDIR;
		goto close_output_file;
	}
	//step4: deep check whether input/output file equal(relative/absolute)
	if(outputIn->i_ino == inputIn->i_ino){
		printk("Error: input and output file are same.\n");
		rc = -EINVAL;
		goto close_output_file;
	}
	//=====by this line, input and output files are ready for output file======//
	/*Stage III write data to output file*/
	//access the opened input file's data
	oldfs = get_fs();
	set_fs(get_ds());

	bytes = (char *)kmalloc(PAGE * sizeof(char) * 2 + 1, GFP_KERNEL);
	if(IS_ERR(bytes)){
		rc = -ENOMEM;
		goto close_output_file;
	}
	//create padding for first line of the chars
	padding = (inputInodeSize % BLOCK != 0) ? BLOCK - inputInodeSize % BLOCK : BLOCK;

	//get IV
	IV = (char *)kmalloc((BLOCK) * sizeof(char) + 1, GFP_KERNEL);
	if(IS_ERR(IV)){
		rc = -ENOMEM;
		goto close_output_file;
	}
	memset(IV, 0, BLOCK);
	i = 0;
	while(i < 16){IV[i] = 'a'; i++;}
	IV[i] = '\0';


	//encrption or decrption begins
	if(kptr->flag == 1){
		//Encrpytion Step 1: padd with first several chars in input file to build the first block.
		firstChars = (char *)kmalloc((BLOCK - padding) * sizeof(char) + 1, GFP_KERNEL);
		if(IS_ERR(firstChars)){
			rc = -ENOMEM;
			goto close_output_file;
		}
		firstBlock = (char *)kmalloc((BLOCK) * sizeof(char) + 1, GFP_KERNEL);
		if(IS_ERR(firstBlock)){
			rc = -ENOMEM;
			goto close_output_file;
		}
		pad = (char *)kmalloc(padding + 1, GFP_KERNEL);
		if(IS_ERR(pad)){
			rc = -ENOMEM;
			goto close_output_file;
		}
  	ele = hexList[padding - 1];
  	for(m = 0; m < padding; m++)
  		pad[m] = ele;
  	pad[padding] = '\0';
  	//read first chars
		rc = readFilePtr->f_op->read(readFilePtr, firstChars, BLOCK - padding, &readFilePtr->f_pos);
		if(rc < 0){
			rc = -EPERM;
			printk("First chars reading failed!\n");
			goto close_output_file;
		}
		firstChars[BLOCK - padding] = '\0';
		// combine padding arrays with first chars to build a block with 16 chars
		// in padding array, the char represents the corresponding pad size - 1;
		m = 0;
		while(m < kptr->passwdLen){
			if(m < padding){
				firstBlock[m] = pad[m];
				m++;
			}
			else{
				int n;
				for(n = 0; n < BLOCK - padding; n++){
					firstBlock[m] = firstChars[n];
					m++;
				}
			}
		}
		firstBlock[BLOCK] = '\0';

		//Encrpytion Step 3: encrypt first block with padding chars and true chars;
		//The consequence is all rest are blocks with no leaks.
		//note: output length buf_len is 32 not 16,which may have problems
		rc = cryption(kptr->passwdBuf, BLOCK, IV, firstBlock, bytes, BLOCK, &buf_len, kptr->flag);
		if(rc < 0){
			rc = -EPERM;
			printk("The encryption is rejected\n");
			goto close_output_file;
		}

		//Encrpytion Step 4: write header and first block
		rc = writeFilePtr->f_op->write(writeFilePtr, res,BLOCK, &writeFilePtr->f_pos);
		if(rc < 0){
			rc = -EPERM;
			printk("Write the hash key to header of output file reading failed!\n");
			goto close_output_file;
		}
		// printk("First block creates key size %i with input size 0 \n", BLOCK);

		rc = writeFilePtr->f_op->write(writeFilePtr, bytes,buf_len, &writeFilePtr->f_pos);
		if(rc < 0){
			rc = -EPERM;
			printk("Write the first block with padded array to output file failed!\n");
			goto close_output_file;
		}
		//**
		// printk("the 0 iteration creates %i cryptos with input's size BLOCK\n", buf_len);
		count = 1;
		//read blocks per Page, encryption and write blocks to output file
		while((inputInodeSize - readFilePtr->f_pos) >= PAGE){
			rc = readFilePtr->f_op->read(readFilePtr, bytes, PAGE, &readFilePtr->f_pos);
			if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto close_output_file;
			}
			bytes[PAGE] = '\0';
			//encryption here
			buf_len = 0;
			rc = cryption(kptr->passwdBuf, BLOCK, IV, bytes, bytes, PAGE, &buf_len, kptr->flag);

			if(rc < 0){
				rc = -EPERM;
				printk("The encryption is rejected\n");
				goto close_output_file;
			}
			//write to output file
			rc = writeFilePtr->f_op->write(writeFilePtr, bytes, buf_len, &writeFilePtr->f_pos);
			if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto close_output_file;
			}
			//**
			// printk("the %i iteration creates %i cryptos with input's size PAGE\n", count++, buf_len);
		}
		//for rest region less then one Page
		if(inputInodeSize - readFilePtr->f_pos > 0){
			int rest = inputInodeSize - readFilePtr->f_pos;
			rc = readFilePtr->f_op->read(readFilePtr, bytes, rest, &readFilePtr->f_pos);
			if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto close_output_file;
			}
			bytes[rest] = '\0';

			//encryption here
			buf_len = 0;
			rc = cryption(kptr->passwdBuf, BLOCK, IV, bytes, bytes, rest, &buf_len, kptr->flag);

			if(rc < 0){
				rc = -EPERM;
				printk("The encryption is rejected\n");
				goto close_output_file;
			}
			//write to output file
			rc = writeFilePtr->f_op->write(writeFilePtr, bytes, buf_len, &writeFilePtr->f_pos);
			if(rc < 0){
				rc = -EPERM;
				printk("Write Blocks failed!\n");
				goto close_output_file;
			}
			//**
			// printk("the rest creates %i cryptos with input's size %i\n", buf_len, rest);

		}
		// printk("rest space is now: %i\n", inputInodeSize - readFilePtr->f_pos);
		// printk("output file's size is %i\n", i_size_read(writeFilePtr->f_path.dentry->d_inode));

		if(inputInodeSize - readFilePtr->f_pos < 0){
			rc = -ESPIPE;
			goto close_output_file;
		}
	}//end if for flag for Encryption

	if(kptr->flag == 0){
		rc = readFilePtr->f_op->read(readFilePtr, bytes, BLOCK, &readFilePtr->f_pos);
		if(rc < 0){
			rc = -EPERM;
			printk("Read Blocks failed!\n");
			goto close_output_file;
		}
		// case 1: the input file has not enough length of key
		if(strlen(bytes) < BLOCK){
			rc = -EINVAL;
			goto close_output_file;
		}
		//**
		// printk("decrypt key: %s\n", bytes);
		// case 2: the key and header info for key does not match
		bytes[BLOCK] = '\0';
		// printk("bytes's length: %i\n", strlen(bytes));
		// printk("bytes: %s\n", bytes);
		// printk("passwd: %s\n", kptr->passwdBuf);
		if(strcmp(bytes, res) != 0){
			rc = -EKEYREJECTED;
			goto close_output_file;
		}

		rc = readFilePtr->f_op->read(readFilePtr, bytes, BLOCK * 2, &readFilePtr->f_pos);
		if(rc < 0){
			rc = -EPERM;
			printk("Read Blocks failed!\n");
			goto close_output_file;
		}
		// printk("decrpyt str: %s\n", bytes);
		// printk("decrypt source len: %i\n", strlen(bytes));
		bytes[BLOCK * 2] = '\0';

		buf_len = 2 * BLOCK;
		rc = cryption(kptr->passwdBuf, BLOCK, IV, bytes, bytes, 2 *BLOCK, &buf_len, kptr->flag);

		// printk("decrypt len: %i\n", buf_len);
		// printk("decrpyt str: %s\n", bytes);

		// write true first several chars into output file
		len = getLengthOfPad(bytes);
		//case 4: the padding len representation is not valid
		if(len == 0){
			rc = -EINVAL;
			goto close_output_file;
		}
		//write to output file for first true several chars
		rc = writeFilePtr->f_op->write(writeFilePtr, bytes + len, BLOCK - len, &writeFilePtr->f_pos);
		if(rc < 0){
			rc = -EPERM;
			printk("Write Blocks failed!\n");
			goto close_output_file;
		}
		
		//begin iteration for the rest in Pages.
		count = 1;
		while((inputInodeSize - readFilePtr->f_pos) >= (PAGE + BLOCK)){
			rc = readFilePtr->f_op->read(readFilePtr, bytes,
	 			PAGE + BLOCK, &readFilePtr->f_pos);
			if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto close_output_file;
			}
			bytes[PAGE+BLOCK] = '\0';

			//encryption here
			buf_len = PAGE;

			rc = cryption(kptr->passwdBuf, BLOCK, IV, bytes, bytes, PAGE + BLOCK, &buf_len, kptr->flag);

			if(rc < 0){
				rc = -EPERM;
				printk("The encryption is rejected\n");
				goto close_output_file;
			}
			//**
			// printk("the %i iteration creates %i cryptos with input's size PAGE + BLOCK\n", count++, buf_len);
			//write to output file
			rc = writeFilePtr->f_op->write(writeFilePtr, bytes, buf_len, &writeFilePtr->f_pos);
			if(rc < 0){
				rc = -EPERM;
				printk("Write Blocks failed!\n");
				goto close_output_file;
			}
		}
		buf_len = inputInodeSize - readFilePtr->f_pos;
		if(buf_len > 0){
			rc = readFilePtr->f_op->read(readFilePtr, bytes, buf_len, &readFilePtr->f_pos);
			if(rc < 0){
				rc = -EPERM;
				printk("Read Blocks failed!\n");
				goto close_output_file;
			}
			bytes[buf_len] = '\0';


			rc = cryption(kptr->passwdBuf, BLOCK, IV, bytes, bytes, buf_len, &buf_len, kptr->flag);

			rc = writeFilePtr->f_op->write(writeFilePtr, bytes, buf_len, &writeFilePtr->f_pos);
			if(rc < 0){
				rc = -EPERM;
				printk("Write Blocks failed!\n");
				goto close_output_file;
			}
		}

		if(inputInodeSize - readFilePtr->f_pos < 0){
			rc = -ESPIPE;
			goto close_output_file;
		}		
	}// end if for decrpytion	

	set_fs(oldfs);
	// finished read-write

	close_output_file:
		filp_close(writeFilePtr,NULL);
	close_null_output_file:
	close_input_file:
		filp_close(readFilePtr,NULL);// note: readFilePtr MUST not be null!
	no_mem_for_struct:
		kfree(kptr);
		if(rc >= 0)// positive number is regarded as normal
			rc = 0;
	return rc;

}

/*
isInputValid function accepts struct myargs as argument, 
checks whether the inputs are legal, including non-null checking,
match checking, same file checking, etc.
The function will return error number if any error occurs, 0 if not.
 */
int isInputValid(void *arg){
	int j = 0;
	myargs *ptr = (myargs *)arg;
	//Stage 0: check validation of inputs
	//case 1 null argument(s) && missing arguments passed
	if(ptr == NULL || ptr->passwdBuf == NULL || ptr->passwdLen == 0 ||
		ptr->inFile == NULL || ptr->outFile == NULL)
		return -EFAULT;

	//case 2 len and buf don't match
  while(ptr->passwdBuf[j] != '\0') 
  	j++;
  // reason: char * cannot be extracted array length information.
	// printk("%i\n", j);
	if(ptr->passwdLen != 16)
		return -EINVAL;
  if(j != ptr->passwdLen)
  	return -EINVAL;

  //case 3 invalid flag
  if(ptr->flag != 0 && ptr->flag != 1)
  	return -EINVAL;

  //case 4 shallow check: whether input and output file points to same file
  if(strcmp(ptr->inFile, ptr->outFile) == 0)
  	return -EINVAL;

  //case 5 file path is too long
  if(strlen(ptr->inFile) > 512 || strlen(ptr->outFile) > 512)
  	return -ENAMETOOLONG;

  return 0;

}
/*
The cryption function execuate for encryption and decryption, respectively.
Descrption: The function run AES in CBC mode for encryption/decryption.
Inputs:
> char *passwdBuf: hashed key
> int passwdLen: the length of hashed key
> char *IV: initialized vector
> char *inFile: input file name
> char *outFile: output file name
> int inFileLen: the length of input file name
> int outFileLen: the length of output file name
> int flag: the flag for cryption mode(1 for encryption, 0 for decryption)
Note: 
*Reference* The core function is inspired by code from 
linux/net/ceph/crypto.c function: ceph_aes_encrypt() and cepth_ase_decrpyt()
 */
int cryption(char *passwdBuf,int passwdLen, char *IV,
 char *inFile, char *outFile, int inFileLen, int *outFileLen, int flag){
	int rc = 0; // error indicator
	char pad[BLOCK];
 	// allocate synchronous block cipher handle
	struct crypto_blkcipher *tfm =  crypto_alloc_blkcipher("cbc(aes)", 0,CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm))// test handle avaliablity.
		return PTR_ERR(tfm);
	struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
	//set key
	crypto_blkcipher_setkey((void*)tfm,passwdBuf,passwdLen);
	if(flag == 1){//encryption
		//sg_in[2] for padding and input, sg_out for output
		struct scatterlist sg_in[2],sg_out[1];
		size_t zero_padding = (inFileLen % BLOCK == 0) ? BLOCK : BLOCK - (inFileLen % BLOCK == 0);
		memset(pad,zero_padding,zero_padding); // allocate padding size of memory
		*outFileLen = inFileLen + zero_padding;
		sg_init_table(sg_in,2);
		sg_set_buf(&sg_in[0],inFile,inFileLen);
		sg_set_buf(&sg_in[1],pad,zero_padding);
		sg_init_table(sg_out,1);
		sg_set_buf(sg_out,outFile,*outFileLen);

		memcpy(crypto_blkcipher_crt(tfm)->iv,IV,crypto_blkcipher_ivsize(tfm));

		rc = crypto_blkcipher_encrypt(&desc,sg_out,sg_in, *outFileLen);
	}
	if(flag == 0){//decryption
		//get the scattered memory contiguously.
		struct scatterlist sg_in[1],sg_out[2];
		int last = 0;
		sg_init_table(sg_in,1);
		sg_set_buf(sg_in,inFile,inFileLen);
		sg_init_table(sg_out,2);
		sg_set_buf(&sg_out[0],outFile,*outFileLen);
		sg_set_buf(&sg_out[1],pad,BLOCK);

		memcpy(crypto_blkcipher_crt(tfm)->iv,IV,crypto_blkcipher_ivsize(tfm));

		rc = crypto_blkcipher_decrypt(&desc,sg_out,sg_in,inFileLen);

		if(inFileLen <= *outFileLen){
			last = ((char*)outFile)[inFileLen - 1];
		}else {
			last = pad[inFileLen - *outFileLen - 1];
		}
		if(last <= inFileLen && last <= BLOCK){
	    *outFileLen = inFileLen - last;
		} else {
		  rc = -EPERM;
		}

	}
	crypto_free_blkcipher(tfm);
	return rc;

}
/*
Function getLengthOfPad gets the padding length indicated by the input
Input: 
> char *inputBlock: char array represents second block of encrypted file, which includes
padding chars and rest chars moduled by Block.
Output: a int type for the length of padding.
Example: if <fileLength> % 16 = 13, then the second block will be
ccccccccccccnic (c for Length 13 padding char, nic for first moduled chars of original file)
 */
int getLengthOfPad(char *inputBlock){
	char lenChar = inputBlock[0];
	switch(lenChar){
		case '0': return 1;
		case '1': return 2;
		case '2': return 3;
		case '3': return 4;
		case '4': return 5;
		case '5': return 6;
		case '6': return 7;
		case '7': return 8;
		case '8': return 9;
		case '9': return 10;
		case 'a': return 11;
		case 'b': return 12;
		case 'c': return 13;
		case 'd': return 14;
		case 'e': return 15;
		case 'f': return 16;
		default:  return 0;
	}
}


static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");


