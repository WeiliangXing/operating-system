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
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

// #include <linux/ioctl.h>

struct patterns pats;
int parse_pattdb(char *data);
int read_pattern_file(char *addr);
int cryption(char *passwdBuf,int passwdLen, char *IV,
char *inFile, char *outFile, int inFileLen, int *outFileLen, int flag);
int getLengthOfPad(char *inputBlock);
int write_like_copy(char *in_dir, char *out_dir);


/*
 * There is no need to lock the amfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int amfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "amfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"amfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct amfs_sb_info), GFP_KERNEL);
	if (!AMFS_SB(sb)) {
		printk(KERN_CRIT "amfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}
	AMFS_SB(sb)->pattdb = pats;
	if(AMFS_SB(sb)->pattdb.err){
		err = AMFS_SB(sb)->pattdb.err;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	amfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &amfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = amfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &amfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	amfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "amfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(AMFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}


struct dentry *amfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
	int ret = 0;
	ret = parse_pattdb(raw_data);
	printk("amfs_mount occurs here!!!\n");

	if(ret >= 0)
		return mount_nodev(fs_type, flags, lower_path_name,
			   amfs_read_super);
	else
		return (struct dentry *)ret;
}

/*
function to parse input from command mount -o options.
char *data: the option string after -o of mount command
*/
int parse_pattdb(char *data){
	char *p;
	int ret = 0;
	struct patterns *patptr = &pats;
	// check1: no option
	if(data == NULL){
		printk("No argument.\n");
		ret = -EINVAL;
		patptr->err = ret;
		goto out;
	}
	p = strsep(&data, "=");
	//check2: argument not pattdb
	if(strcmp(p, "pattdb") != 0){
		printk("Wrong option.\n");
		ret = -EINVAL;
		patptr->err = ret;
		goto out;
	}
	p = strsep(&data, "=");
	//check3: argument empty
	if(strcmp(p, "") == 0){
		printk("No option content.\n");
		ret = -EINVAL;
		patptr->err = ret;
		goto out;
	}
	patptr->passwd = "12345678";
	patptr->db_dir = (char *)kmalloc(strlen(p) * sizeof(char), GFP_KERNEL);
	if(IS_ERR(patptr->db_dir)){
		ret = -ENOMEM;
		patptr->err = ret;
		goto out;
	}
	strcpy(patptr->db_dir, p);
	//check whether is valid file address and relative problems
	//put reading result into super_block's amfs_sb_info struct patterns
	ret = read_pattern_file(p);

	//test for encrypt
	// ret = amfs_crypt(patptr, 1);
	// ret = amfs_crypt(patptr, 0);
	// ret = amfs_crypt(patptr, 1);
	// ret = write_like_copy("temp.db", patptr->db_dir);
	// ret = amfs_crypt(patptr, 0);
	// ret = write_like_copy("temp.db", patptr->db_dir);


	// test for write 
	// char *text = "Hello world find";
	// int is_matched = amfs_strcmp(patptr, text);
	//test for read a file
	// char *read_dir = "test.txt";
	// int is_matched = amfs_read_file_strcmp(patptr, read_dir);
	
	out:
	return ret;
}
/*
function to parse the db file into super_block
char *addr: directory of .db file
*/
int read_pattern_file(char *addr){
	char *ptr;
	int ret = 0;
	struct file *readFilePtr = NULL;//for input file pointer.
	struct inode *inputIn = NULL;//for get inode of input file
	size_t inputInodeSize = 0;// for get size of input file
	umode_t inputInodeMode = 0;//for get mode of input file
	mm_segment_t oldfs;
	char *bytes; // for reading of input file.
	char *perLine;
	int count_page = 1;
	int count_line = 0;
	struct patterns *patptr = &pats;

	patptr->err = -EINVAL;
	if(addr == NULL){
		printk("Null input\n");
		ret = -EFAULT;
		patptr->err = ret;
		goto out;
	}
	if(strlen(addr) > 512){
		printk("Too long input\n");
		ret = -ENAMETOOLONG;
		patptr->err = ret;
		goto out;
	}
	ptr = addr;

	//read input file, check validness.
	readFilePtr = filp_open(ptr, O_RDONLY, 0);
	if(!readFilePtr || IS_ERR(readFilePtr) || readFilePtr < 0){
		printk("Open input file error: %d\n", (int)PTR_ERR(readFilePtr));
		ret = -ENOENT;
		patptr->err = ret;
		goto out; 
	}

	//check whether has read permission:		
	if(!readFilePtr->f_op->read){
		printk("Read input file Permission Denied!\n");
		ret = -EPERM;
		patptr->err = ret;
		goto close_filp;
	}
	//get input file size and check whether null
	inputIn = readFilePtr->f_path.dentry->d_inode;
	inputInodeSize = i_size_read(inputIn);

	if(inputInodeSize <= 0){
		printk("Error: input file's size is %zu\n",inputInodeSize);
		ret= -EPERM;
		patptr->err = ret;
		goto close_filp;
	}
	//check whether input file is regular
	inputInodeMode = inputIn->i_mode;
	if(S_ISREG(inputInodeMode) == 0){
		printk("Error: The file is not regular: input file.\n");
		ret = -EISDIR;
		patptr->err = ret;
		goto close_filp;
	}
	//read file
	oldfs = get_fs();
	set_fs(get_ds());
	bytes = (char *)kmalloc(PAGE * sizeof(char) * 2 + 1, GFP_KERNEL);
	if(IS_ERR(bytes)){
		ret = -ENOMEM;
		patptr->err = ret;
		goto free_bytes;
	}

	/*rules of reading: 
	Max page reading: 10, max line got: 100;
	if one line is broken due to page reading, it creates two lines patterns and store it.
	*/
	while(count_page <= MAX_PATTERN_PAGES &&
	 ((ret = readFilePtr->f_op->read(readFilePtr, bytes,
	 			PAGE, &readFilePtr->f_pos)) > 0)){
		bytes[readFilePtr->f_pos] = '\n';
		bytes[readFilePtr->f_pos + 1] = '\0';
		// printk("the str is:\n%s\n", bytes);
		// printk("read line by line: \n");

		while(count_line < MAX_PATTERNS &&
		 strcmp(perLine = strsep(&bytes, "\n"),"") != 0){
		 	perLine[strlen(perLine)] = '\0';
			// printk("%s with count: %i\n", perLine, count_line);
			patptr->pat[count_line] = (char *)kmalloc(PAGE * sizeof(char), GFP_KERNEL);
			if(IS_ERR(patptr->pat[count_line])){
				ret = -ENOMEM;
				patptr->err = ret;
				goto free_bytes;
			}
			strcpy(patptr->pat[count_line],perLine);
			count_line += 1;
		}
		patptr->pats_len = count_line;

		if(count_line > MAX_PATTERNS) break;

		count_page += 1;
	}
	set_fs(oldfs);
	ret = amfs_crypt(patptr, 1);
	
	patptr->err = 0;

	amfs_sort_pat(patptr);
	amfs_remove_dup_pat(patptr);

	free_bytes:
		kfree(bytes);
	close_filp:
		filp_close(readFilePtr, NULL);
	out:
	return ret;
}

//*reference* from Linux/lib/sort.c
// heapsort method with O(m * nlgn) time complexity where n is the size of patterns
//m is largest size of each pattern
void amfs_sort_pat(struct patterns *patptr){
	int num = patptr->pats_len;
	char **base = patptr->pat;

	int i = num/2 - 1;
   	int n = num, c, r;
  	/*heapify*/
  	for(; i >= 0; i-= 1){
    	for(r = i; r * 2 + 1 < n; r = c){
      		c = r * 2 + 1;
      		if(c < n - 1 && strcmp(*(base + c), *(base + c + 1)) < 0)
        		c += 1;
      		if(strcmp(*(base + r), *(base + c)) >= 0)
        		break;
      		amfs_swap_pat(base + r, base + c);
    	}
  	}
  	/*sort*/
    for (i = n - 1; i > 0; i -= 1) {
        amfs_swap_pat(base, base + i);
        for (r = 0; r * 2 + 1 < i; r = c) {
            c = r * 2 + 1;
            if (c < i - 1 && strcmp(*(base + c), *(base + c + 1))< 0)
                c += 1;
            if (strcmp(*(base + r), *(base + c))>= 0)
                break;
            amfs_swap_pat(base + r, base + c);
        }
    }
  	// printk("in sort len: %i\n", patptr->pats_len);

}

void amfs_swap_pat(char **a, char **b){
	char *t = *a;
	*a = *b;
	*b = t;
}

/*list the patterns in the pattern file*/
char **amfs_list_pat(struct patterns *patptr){
  	return patptr->pat;
}

/*function to remove any duplicates for patterns file
mechanism: put duplicates to end of array, reset the length of whole array
note: it means the rest of array outside the patptr->pats_len is not necessary null;
*/
void amfs_remove_dup_pat(struct patterns *patptr){
  	char **base = patptr->pat;
  	int i;
  	int id = 1;
  	for(i = 1; i < patptr->pats_len; i++){
    	if(strcmp(*(base + i), *(base + i - 1)) != 0){
      		strcpy(*(base + id), *(base + i));
      		id += 1;
    	}
  	}
  	patptr->pats_len = id;
}

/*
function for binary search for a string; this is exact match with same content and length;
return index of the array if matches;
return -1 if not matches;
*/
int amfs_search_pat(struct patterns *patptr, char *str){
  	char **base = patptr->pat;
  	int size = patptr->pats_len;
  	int mid, lo = 0, hi = size - 1;
  	while(lo <= hi){
  		mid = lo + (hi - lo) / 2;
  		if(strcmp(*(base + mid), str) == 0)
  			return mid;
  		else if(strcmp(*(base + mid), str) > 0)
  			hi = mid - 1;
  		else
  			lo = mid + 1;
  	}
  	return -1;
}

/*
function to remove the pattern.
return 0 if successfully removed
return -1 if failed to remove
check whether str exist in amfs, whether amfs is empty also
*/
int amfs_remove_pat(struct patterns *patptr, char *str){
  	char **base = patptr->pat;
  	int size = patptr->pats_len;
  	int idx;
  	if(*(base) == NULL){ //empty pattern file
  		printk("Empty pattern file!\n");
  		return -1;
  	}
  	idx = amfs_search_pat(patptr, str);
  	if(idx == -1){// str not exist
  		printk("The target does not exist in pattern db!\n");
  		return -1;
  	}
  	amfs_swap_pat(base + idx, base + size - 1);
  	patptr->pats_len -= 1;
  	amfs_sort_pat(patptr);

  	return 0;
}

/*
function to add the pattern to sb.
return 0 if successfully add
return negative if failed to add
check whether str exist in amfs, whether amfs is full, or error when kmalloc
*/
int amfs_add_pat(struct patterns *patptr, char *str){
  	char **base = patptr->pat;
  	int size = patptr->pats_len;
  	int idx;

  	if(size == MAX_PATTERNS){
  		printk("The pattern db is full!\n");
  		return -EINVAL;
  	}
  	idx = amfs_search_pat(patptr, str);
  	if(idx != -1){
  		printk("The target exists in db!\n");
  		return -EINVAL;
  	}

  	if(*(base + size) == NULL){
  		*(base + size) = (char *)kmalloc(PAGE * sizeof(char), GFP_KERNEL);
  		if(IS_ERR(*(base + size))){
  			return -ENOMEM;
  		}
  	} 

  	strcpy(*(base + size), str);
  	patptr->pats_len += 1;
  	amfs_sort_pat(patptr);

  	return 0;
}

int write_pattern_file(struct patterns *patptr, char *dir){
  	char **base = patptr->pat;
  	int size = patptr->pats_len;
  	int err = 0;
  	// char *dir = patptr->db_dir;
  	// char *dir = "/usr/src/hw2-wxing/fs/amfs/patoutput.db";//for test purpose

	struct inode *outputIn = NULL;//for get inode of output file
	umode_t outputInodeMode = 0;//for get mode of output file
	struct file *writeFilePtr = NULL;//for output file pointer.
	size_t outputInodeSize = 0;// for get size of output file
	mm_segment_t oldfs;
	int i;
	char *temp;
	loff_t pos = 0;

  	// check the avaialability of output file
	//check whether can open:			
	writeFilePtr = filp_open(dir, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if(!writeFilePtr || IS_ERR(writeFilePtr)){
		printk("Open output file error: %d\n", (int)PTR_ERR(writeFilePtr));
		err = -ENOENT;
		goto out;
	}
	//check whether could be write
	if(!writeFilePtr->f_op->write){
		printk("Read output file Permission Denied!\n");
		err = -EPERM;
		goto close_filp;
	}
	//check regularity of the output file
	outputIn = writeFilePtr->f_path.dentry->d_inode;
	outputInodeSize = i_size_read(outputIn);
	outputInodeMode = outputIn->i_mode;
	if(S_ISREG(outputInodeMode) == 0){
		printk("Error: The file is not regular: output file.\n");
		err = -EISDIR;
		goto close_filp;
	}

	//write file
	oldfs = get_fs();
	set_fs(get_ds());
	temp = "\n";

	for(i = 0; i < size; i++){
		vfs_write(writeFilePtr, *(base + i), strlen(*(base + i)), &pos);
		vfs_write(writeFilePtr, temp, strlen(temp), &pos);
		// printk("write str: %s\n", *(base + i));

	}

	set_fs(oldfs);
	printk("finish writing\n");
	
	close_filp:
		// filp_close(writeFilePtr, NULL);
	out:
  		// patptr->err = err;
  	return err;
}

int amfs_strcmp(struct patterns *patptr, char *str){
	int ret = 0;
	char **base = patptr->pat;
  	int size = patptr->pats_len;
  	int i;

	// printk("strcmp begins!\n");
  	for(i = 0; i < size; i++){
  		if(strstr(str, *(base + i)) != NULL){
			// printk("needle matches!\n");
			ret = 1;
			return ret;
		}
  	}
	// printk("needle does not match!\n");

	return ret;
}

int amfs_read_file_strcmp(struct patterns *patptr, struct file *file){
	int ret = 0;
	struct file *readFilePtr = file;//for input file pointer.
	struct inode *inputIn = NULL;//for get inode of input file
	size_t inputInodeSize = 0;// for get size of input file
	mm_segment_t oldfs;
	char *bytes; // for reading of input file.
	int err;
	char *perLine;

	//check whether has read permission:		
	if(!readFilePtr->f_op->read){
		printk("Read input file Permission Denied!\n");
		goto close_filp;
	}
	//get input file size and check whether null
	inputIn = readFilePtr->f_path.dentry->d_inode;
	inputInodeSize = i_size_read(inputIn);

	if(inputInodeSize <= 0){
		printk("Input file's size is %zu\n",inputInodeSize);
		goto close_filp;
	}

	//read file
	oldfs = get_fs();
	set_fs(get_ds());
	bytes = (char *)kmalloc(PAGE * sizeof(char) * 2 + 1, GFP_KERNEL);
	if(IS_ERR(bytes)){
		printk("Not enough Memory, matching fails!\n");
		goto free_bytes;
	}


	while((err = readFilePtr->f_op->read(readFilePtr, bytes,
	 			PAGE, &readFilePtr->f_pos)) > 0){
		bytes[readFilePtr->f_pos] = '\n';
		bytes[readFilePtr->f_pos + 1] = '\0';


		while(strcmp(perLine = strsep(&bytes, "\n"),"") != 0){
		 	perLine[strlen(perLine)] = '\0';
		 	ret = amfs_strcmp(patptr, perLine);
		 	if(ret == 1){goto close_fs;}
		}
	}
	printk("needle does not match!\n");

	close_fs:
		set_fs(oldfs);

	free_bytes:
		kfree(bytes);
	close_filp:
		filp_close(readFilePtr, NULL);
	return ret;
}

int amfs_crypt(struct patterns *patptr, int mode){
	int err = 0;
	char *pwd;
	char *IV = "aaaaaaaaaaaaaaaa";
	struct file *readFilePtr = NULL;//for input file pointer.
	struct file *writeFilePtr = NULL;//for output file pointer.
	char *dir = patptr->db_dir;
	char *out_dir = "temp.db";
	// char *dir;
	// char *out_dir;
	size_t inputInodeSize = 0;// for get size of input file
	char *bytes;
	char ele;
	int padding = 0;
	char hexList[16] = "0123456789abcdef";//hex dictionary for lookup
	char *pad = NULL;
	mm_segment_t oldfs;
	int m;
	char *firstChars = NULL;
	char *firstBlock = NULL;
	int buf_len;
	int len;


	// if(mode == 1){
	// 	dir = "test.db";
	// 	out_dir = "temp.db";
	// }
	// if(mode == 0){
	// 	dir = "test.db";
	// 	out_dir = "temp.db";
	// }

	pwd = kmalloc(BLOCK * sizeof(char), GFP_KERNEL);
	if(IS_ERR(pwd)){
		err = -ENOMEM;
		printk("MEMORY is not enough!\n");
		goto out;
	}

	err = amfs_gen_key(patptr, pwd);
	if(err < 0){
		goto free_pwd;
	}

	readFilePtr = filp_open(dir, O_EXCL, 0);
	if(!readFilePtr || IS_ERR(readFilePtr)){
		printk("Open input file error: %d\n", (int)PTR_ERR(readFilePtr));
		err = -ENOENT;
		goto free_pwd; 
	}

	inputInodeSize = i_size_read(readFilePtr->f_path.dentry->d_inode);

	writeFilePtr = filp_open(out_dir, O_WRONLY|O_CREAT|O_TRUNC, readFilePtr->f_path.dentry->d_inode->i_mode);
	if(!writeFilePtr || IS_ERR(writeFilePtr)){
		printk("Open output file error: %d\n", (int)PTR_ERR(writeFilePtr));
		err = -ENOENT;
		writeFilePtr = NULL;
		goto close_input;
	}

	oldfs = get_fs();
	set_fs(get_ds());

	bytes = (char *)kmalloc(PAGE * sizeof(char) * 2 + 1, GFP_KERNEL);
	if(IS_ERR(bytes)){
		err = -ENOMEM;
		goto close_output;
	}

	//create padding for first line of the chars
	padding = (inputInodeSize % BLOCK != 0) ? BLOCK - inputInodeSize % BLOCK : BLOCK;

	//stage1: read first blocks and padding and write it
	if(mode == 1){
		//Encrpytion Step 1: padd with first several chars in input file to build the first block.
		firstChars = (char *)kmalloc((BLOCK - padding) * sizeof(char) + 1, GFP_KERNEL);

		if(IS_ERR(firstChars)){
			err = -ENOMEM;
			goto free_bytes;
		}
		firstBlock = (char *)kmalloc((BLOCK) * sizeof(char) + 1, GFP_KERNEL);
		if(IS_ERR(firstBlock)){
			err = -ENOMEM;
			goto free_firstChars;
		}
		pad = (char *)kmalloc(padding + 1, GFP_KERNEL);
		if(IS_ERR(pad)){
			err = -ENOMEM;
			goto free_firstBlock;
		}
	  	ele = hexList[padding - 1];
	  	for(m = 0; m < padding; m++)
	  		pad[m] = ele;
	  	pad[padding] = '\0';

		err = readFilePtr->f_op->read(readFilePtr, firstChars, BLOCK - padding, &readFilePtr->f_pos);
		if(err < 0){
			err = -EPERM;
			printk("First chars reading failed!\n");
			goto free_pad;
		}
		firstChars[BLOCK - padding] = '\0';
		// combine padding arrays with first chars to build a block with 16 chars
		// in padding array, the char represents the corresponding pad size - 1;
		m = 0;
		while(m < BLOCK){
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

		err = cryption(pwd, BLOCK, IV, firstBlock, bytes, BLOCK, &buf_len, 1);
		if(err < 0){
			err = -EPERM;
			printk("The encryption is rejected\n");
			goto free_pad;
		}

		err = writeFilePtr->f_op->write(writeFilePtr, bytes,buf_len, &writeFilePtr->f_pos);
		if(err < 0){
			err = -EPERM;
			printk("Write the first block with padded array to output file failed!\n");
			goto free_pad;
		}

		// printk("bytes: %s\n",bytes);

		//read blocks per Page, encryption and write blocks to output file
		while((inputInodeSize - readFilePtr->f_pos) >= PAGE){
			err = readFilePtr->f_op->read(readFilePtr, bytes, PAGE, &readFilePtr->f_pos);
			if(err < 0){
				err = -EPERM;
				printk("Read Blocks failed!\n");
				goto free_pad;
			}
			bytes[PAGE] = '\0';
			//encryption here
			buf_len = 0;
			err = cryption(pwd, BLOCK, IV, bytes, bytes, PAGE, &buf_len, 1);

			if(err < 0){
				err = -EPERM;
				printk("The encryption is rejected\n");
				goto free_pad;
			}
			//write to output file
			err = writeFilePtr->f_op->write(writeFilePtr, bytes, buf_len, &writeFilePtr->f_pos);
			if(err < 0){
				err = -EPERM;
				printk("Read Blocks failed!\n");
				goto free_pad;
			}
		}
		//for rest region less then one Page
		if(inputInodeSize - readFilePtr->f_pos > 0){
			int rest = inputInodeSize - readFilePtr->f_pos;
			err = readFilePtr->f_op->read(readFilePtr, bytes, rest, &readFilePtr->f_pos);
			if(err < 0){
				err = -EPERM;
				printk("Read Blocks failed!\n");
				goto free_pad;
			}
			bytes[rest] = '\0';

			//encryption here
			buf_len = 0;
			err = cryption(pwd, BLOCK, IV, bytes, bytes, rest, &buf_len, 1);

			if(err < 0){
				err = -EPERM;
				printk("The encryption is rejected\n");
				goto free_pad;
			}
			//write to output file
			err = writeFilePtr->f_op->write(writeFilePtr, bytes, buf_len, &writeFilePtr->f_pos);
			if(err < 0){
				err = -EPERM;
				printk("Write Blocks failed!\n");
				goto free_pad;
			}

		}

		if(inputInodeSize - readFilePtr->f_pos < 0){
			err = -ESPIPE;
			goto free_pad;
		}
		printk("Encypt done!\n");


	  	free_pad:
	  		kfree(pad);
	  	free_firstBlock:
	  		kfree(firstBlock);
	  	free_firstChars:
	  		kfree(firstChars);
	}
	if(mode == 0){
		err = readFilePtr->f_op->read(readFilePtr, bytes, BLOCK * 2, &readFilePtr->f_pos);
		if(err < 0){
			err = -EPERM;
			printk("Read Blocks failed!\n");
			goto free_bytes;
		}
		bytes[BLOCK * 2] = '\0';
		buf_len = 2 * BLOCK;
		err = cryption(pwd, BLOCK, IV, bytes, bytes, 2 *BLOCK, &buf_len, 0);
		if(err < 0){
			err = -EPERM;
			printk("The encryption is rejected\n");
			goto free_bytes;
		}
		len = getLengthOfPad(bytes);
		if(len == 0){
			err = -EINVAL;
			goto free_bytes;
		}

		err = writeFilePtr->f_op->write(writeFilePtr, bytes + len, BLOCK - len, &writeFilePtr->f_pos);
		if(err < 0){
			err = -EPERM;
			printk("Write Blocks failed!\n");
			goto free_bytes;
		}

		while((inputInodeSize - readFilePtr->f_pos) >= (PAGE + BLOCK)){
			err = readFilePtr->f_op->read(readFilePtr, bytes,
	 			PAGE + BLOCK, &readFilePtr->f_pos);
			if(err < 0){
				err = -EPERM;
				printk("Read Blocks failed!\n");
				goto free_bytes;
			}
			bytes[PAGE+BLOCK] = '\0';

			//encryption here
			buf_len = PAGE;

			err = cryption(pwd, BLOCK, IV, bytes, bytes, PAGE + BLOCK, &buf_len, 0);

			if(err < 0){
				err = -EPERM;
				printk("The encryption is rejected\n");
				goto free_bytes;
			}
			//write to output file
			err = writeFilePtr->f_op->write(writeFilePtr, bytes, buf_len, &writeFilePtr->f_pos);
			if(err < 0){
				err = -EPERM;
				printk("Write Blocks failed!\n");
				goto free_bytes;
			}
		}
		buf_len = inputInodeSize - readFilePtr->f_pos;
		if(buf_len > 0){
			err = readFilePtr->f_op->read(readFilePtr, bytes, buf_len, &readFilePtr->f_pos);
			if(err < 0){
				err = -EPERM;
				printk("Read Blocks failed!\n");
				goto free_bytes;
			}
			bytes[buf_len] = '\0';

			err = cryption(pwd, BLOCK, IV, bytes, bytes, buf_len, &buf_len, 0);

			err = writeFilePtr->f_op->write(writeFilePtr, bytes, buf_len, &writeFilePtr->f_pos);
			if(err < 0){
				err = -EPERM;
				printk("Write Blocks failed!\n");
				goto free_bytes;
			}
		}

		if(inputInodeSize - readFilePtr->f_pos < 0){
			err = -ESPIPE;
			goto free_bytes;
		}
		printk("Decryption done!\n");		

	}

	free_bytes:
		kfree(bytes);
	close_output:
		set_fs(oldfs);
		filp_close(writeFilePtr, NULL);
	close_input:
		filp_close(readFilePtr, NULL);
	free_pwd:
		kfree(pwd);
		if(err >= 0)
			err = write_like_copy(out_dir, patptr->db_dir);
	out:
	return err;
}


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

int write_like_copy(char *in_dir, char *out_dir){
	int err = 0;
	struct file *readFilePtr = NULL;//for input file pointer.
	struct file *writeFilePtr = NULL;//for output file pointer.
	size_t inputInodeSize = 0;// for get size of input file
	char *bytes;
	mm_segment_t oldfs;

	readFilePtr = filp_open(in_dir, O_EXCL, 0);
	if(!readFilePtr || IS_ERR(readFilePtr)){
		printk("Open input file error: %d\n", (int)PTR_ERR(readFilePtr));
		err = -ENOENT;
		goto out; 
	}

	inputInodeSize = i_size_read(readFilePtr->f_path.dentry->d_inode);

	writeFilePtr = filp_open(out_dir, O_WRONLY|O_CREAT|O_TRUNC, readFilePtr->f_path.dentry->d_inode->i_mode);
	if(!writeFilePtr || IS_ERR(writeFilePtr)){
		printk("Open output file error: %d\n", (int)PTR_ERR(writeFilePtr));
		err = -ENOENT;
		writeFilePtr = NULL;
		goto close_input;
	}

	oldfs = get_fs();
	set_fs(get_ds());

	bytes = (char *)kmalloc(PAGE * sizeof(char) * 2 + 1, GFP_KERNEL);
	if(IS_ERR(bytes)){
		err = -ENOMEM;
		goto close_output;
	}

	while(readFilePtr->f_pos < inputInodeSize){
		err = readFilePtr->f_op->read(readFilePtr, bytes,
	 			PAGE, &readFilePtr->f_pos);
		if(err < 0){
			err = -EPERM;
			printk("Read failed!\n");
			goto free_bytes;
		}
		err = vfs_write(writeFilePtr, bytes, readFilePtr->f_pos, &writeFilePtr->f_pos);
		if(err < 0){
			err = -EPERM;
			printk("Write failed!\n");
			goto free_bytes;
		}
	}

	free_bytes:
		kfree(bytes);
	close_output:
		set_fs(oldfs);
		filp_close(writeFilePtr, NULL);
	close_input:
		filp_close(readFilePtr, NULL);
	out:
	return err;
	
}

int amfs_gen_key(struct patterns *patptr, char *pwd){
	int err = 0;
	char *passwd = patptr->passwd;
	char *pad = "00000000";
	struct hash_desc desc;
  	struct scatterlist sg;
  	struct crypto_hash *tfm;
	char *pad_passwd = kmalloc(BLOCK * sizeof(char), GFP_KERNEL);

	if(IS_ERR(pad_passwd)){
		err = -ENOMEM;
		printk("MEMORY is not enough!\n");
		goto out;
	}
	strcpy(pad_passwd, passwd);
	strcat(pad_passwd, pad);
	pad_passwd[BLOCK] = '\0';

	sg_init_one(&sg, pad_passwd, BLOCK);

	tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm)){
		err = -PTR_ERR(tfm);
		goto free_pwd;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	err = crypto_hash_init(&desc);
	if(err){
		err = -EKEYREJECTED;
		goto free_pwd;
	}

	err = crypto_hash_update(&desc, &sg, BLOCK);
	if(err){
		err = -EKEYREJECTED;
		goto free_pwd;
	}
	err = crypto_hash_final(&desc, pwd);
	if(err){
		err = -EKEYREJECTED;
		goto free_pwd;
	}
	pwd[BLOCK] = '\0';
	crypto_free_hash(tfm);

	free_pwd:
		kfree(pad_passwd);
	out:
	return err;
}

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

static struct file_system_type amfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= AMFS_NAME,
	.mount		= amfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(AMFS_NAME);

static int __init init_amfs_fs(void)
{
	int err;

	pr_info("Registering amfs " AMFS_VERSION "\n");

	err = amfs_init_inode_cache();
	if (err)
		goto out;
	err = amfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&amfs_fs_type);
out:
	if (err) {
		amfs_destroy_inode_cache();
		amfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_amfs_fs(void)
{
	amfs_destroy_inode_cache();
	amfs_destroy_dentry_cache();
	unregister_filesystem(&amfs_fs_type);
	pr_info("Completed amfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("AMFS " AMFS_VERSION
		   " (http://amfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_amfs_fs);
module_exit(exit_amfs_fs);
