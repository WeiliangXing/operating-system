#include <linux/slab.h> 
#include <asm/uaccess.h>
#include <linux/fs.h>
#include "strops.h"
#include "common.h"
#include "utils.h"

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/delay.h>

/*
  function to handle files string operation
*/
int strops_files(void *arg){
    int rc = 0;
    struct strops_args *ptr = (struct strops_args *)arg;
    struct strops_args *kptr = NULL;

    /*check validation of input */
    rc = isInputValid(ptr);
    if(rc < 0) 
        goto out;

    /*copy_from_user into kernel */
    kptr = (struct strops_args *)kmalloc(sizeof(struct strops_args), GFP_KERNEL);
    if(IS_ERR(kptr)){
        rc = -ENOMEM;
        goto out;
    }
    if(copy_from_user(kptr, ptr, sizeof(struct strops_args))){
        rc = -EFAULT;
        goto free_kptr;
    }

    /* begin file strings operation mode*/
    rc = search_pat(kptr);
    if(rc < 0)
        goto free_kptr;

    if(kptr->flag == 1 || kptr->flag == 2){
        if(kptr->res_len == 0){
            printk("No found pattern; Operation quit.\n");
            goto free_kptr;
        }
        rc = write_pat(kptr, 0);
        if(rc < 0)
            goto free_kptr;	
    }

    if(copy_to_user(ptr, kptr, sizeof(struct strops_args))){
        rc = -EFAULT;
        goto free_kptr;
    }
 free_kptr:
    kfree(kptr);
 out:
    return rc;
}

/*search pattern*/
int search_pat(void *arg){
    int rc = 0;
    struct strops_args *kptr = (struct strops_args *)arg;
    struct file *readFilePtr = NULL;/*for input file pointer.*/
    size_t inputInodeSize = 0;/* for get size of input file*/

    mm_segment_t oldfs;
    char *bytes;/* bytes from input file*/
    char *temp;
    char *res;
    int page_count = 0;

    readFilePtr = filp_open(kptr->in_file, O_EXCL, 0);
    if(!readFilePtr || IS_ERR(readFilePtr)){
        printk("Open input file error: %d\n", (int)PTR_ERR(readFilePtr));
        rc = -ENOENT;
        readFilePtr = NULL;
        goto out; 
    }

    rc = isInFileValid(readFilePtr);
    if(rc < 0)
        goto close_input_file;

    inputInodeSize = i_size_read(readFilePtr->f_path.dentry->d_inode);

    bytes = (char *)kmalloc(PAGE * sizeof(char) + 1, GFP_KERNEL);
    if(IS_ERR(bytes)){
        rc = -ENOMEM;
        goto close_input_file;
    }
    oldfs = get_fs();
    set_fs(get_ds());

    while((inputInodeSize - readFilePtr->f_pos) > 0){
        if(kptr->res_len == MAX_OCC){
            printk("find more than maximum(100) number of results! Truncate.\n");
            break;
        }
        if(inputInodeSize - readFilePtr->f_pos >= PAGE){
            rc = readFilePtr->f_op->read(readFilePtr, bytes, PAGE, &readFilePtr->f_pos);
            if(rc < 0){
                rc = -EPERM;
                printk("Read Blocks failed!\n");
                goto set_oldfs;
            }
            bytes[PAGE] = '\0';
            temp = bytes;

            while((res = strstr(temp, kptr->old_str)) != NULL){
                int dis = res - bytes;
                if(kptr->res_len == MAX_OCC){
                    printk("find more than maximum(100) number of results! Truncate.\n");
                    goto set_oldfs;
                }
                if(page_count == 0){
                    kptr->res[(kptr->res_len)++] = dis;
                }
                else{
                    kptr->res[(kptr->res_len)++] = dis - kptr->old_len * page_count + (PAGE) * page_count;
                }

                temp = kptr->old_len + res;
            }
            page_count++;
            readFilePtr->f_pos -= kptr->old_len;

        }else{
            int rest = inputInodeSize - readFilePtr->f_pos;
            rc = readFilePtr->f_op->read(readFilePtr, bytes, rest, &readFilePtr->f_pos);
            if(rc < 0){
                rc = -EPERM;
                printk("Read Blocks failed!\n");
                goto set_oldfs;
            }
            bytes[rest] = '\0';
            temp = bytes;
            while((res = strstr(temp, kptr->old_str)) != NULL){
                int dis = res - bytes;
                if(kptr->res_len == MAX_OCC){
                    printk("find more than maximum(100) number of results! Truncate.\n");
                    goto set_oldfs;
                }
                if(page_count != 0)
                    kptr->res[(kptr->res_len)++] = dis - kptr->old_len * page_count + (PAGE) * page_count;
                else
                    kptr->res[(kptr->res_len)++] = dis;

                temp = kptr->old_len + res;
            }
        }
    }

 set_oldfs:
    set_fs(oldfs);
    kfree(bytes);
 close_input_file:
    filp_close(readFilePtr, NULL);

 out:
    return rc;

}

/*write pattern*/
int write_pat(void *arg, int mode){
    int i;
    int rc = 0;
    struct strops_args *kptr = (struct strops_args *)arg;
    struct file *readFilePtr = NULL;/*for input file pointer.*/
    size_t inputInodeSize = 0;/* for get size of input file*/

    struct file *writeFilePtr = NULL;/*for output file pointer.*/
    char *out_dir = "temp.txt";

    mm_segment_t oldfs;
    char *bytes;/* bytes from input file*/
    char *temp;

    if(mode == 0){ /* write to temp file*/
        readFilePtr = filp_open(kptr->in_file, O_EXCL, 0);
    }
    else{
        readFilePtr = filp_open(out_dir, O_EXCL, 0);
    }
    if(!readFilePtr || IS_ERR(readFilePtr)){
        printk("Open input file error: %d\n", (int)PTR_ERR(readFilePtr));
        rc = -ENOENT;
        readFilePtr = NULL;
        goto out; 
    }

    rc = isInFileValid(readFilePtr);
    if(rc < 0)
        goto close_input_file;

    inputInodeSize = i_size_read(readFilePtr->f_path.dentry->d_inode);

    /*check whether can open:*/
    if(mode == 0){		
        writeFilePtr = filp_open(out_dir, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    }else{
        writeFilePtr = filp_open(kptr->in_file, O_WRONLY|O_CREAT|O_TRUNC, 0644);

    }
    if(!writeFilePtr || IS_ERR(writeFilePtr)){
        printk("Open output file error: %d\n", (int)PTR_ERR(writeFilePtr));
        rc = -ENOENT;
        writeFilePtr = NULL;
        goto close_input_file;
    }

    rc = isOutFileValid(writeFilePtr); 
    if(rc < 0)
        goto close_output_file;

    bytes = (char *)kmalloc(PAGE * sizeof(char) + 1, GFP_KERNEL);
    if(IS_ERR(bytes)){
        rc = -ENOMEM;
        goto close_output_file;
    }
    temp = (char *)kmalloc(PAGE * sizeof(char) + 1, GFP_KERNEL);
    if(IS_ERR(temp)){
        rc = -ENOMEM;
        goto free_bytes;
    }
    oldfs = get_fs();
    set_fs(get_ds());

    if(mode == 0){/*write new file to temp*/
        if(kptr->flag == 1){/* delete pattern*/
            char *index;
            int page_count = 1;
            int dist = 0;
            while((inputInodeSize - readFilePtr->f_pos) > 0){
                if(inputInodeSize - readFilePtr->f_pos >= PAGE){
                    int pos = readFilePtr->f_pos;
                    dist = 0;

                    rc = readFilePtr->f_op->read(readFilePtr, bytes, PAGE, &readFilePtr->f_pos);
                    if(rc < 0){
                        rc = -EPERM;
                        printk("Read Blocks failed!\n");
                        goto set_oldfs;
                    }
                    bytes[PAGE] = '\0';
                    index = bytes;

                    for(i = 0; i < kptr->res_len; i++){
                        if(kptr->res[i] < pos) continue;
                        if(kptr->res[i] > page_count * PAGE) continue;
                        dist = kptr->res[i] % PAGE - (index - bytes);
                        strncpy(temp, index, dist);
                        temp[dist] = '\0';
                        index += dist + kptr->old_len;
                        rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                        if(rc < 0){
                            rc = -EPERM;
                            printk("Write the hash key to header of output file reading failed!\n");
                            goto set_oldfs;
                        }

                    }
                    strncpy(temp, index, PAGE - (index - bytes));
                    temp[PAGE - (index - bytes)] = '\0';
                    rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                    if(rc < 0){
                        rc = -EPERM;
                        printk("Write the hash key to header of output file reading failed!\n");
                        goto set_oldfs;
                    }	
                    page_count++;				

                }else{
                    int rest = inputInodeSize - readFilePtr->f_pos;
                    int pos = readFilePtr->f_pos;
                    dist = 0;
                    rc = readFilePtr->f_op->read(readFilePtr, bytes, rest, &readFilePtr->f_pos);
                    if(rc < 0){
                        rc = -EPERM;
                        printk("Read Blocks failed!\n");
                        goto set_oldfs;
                    }
                    bytes[rest] = '\0';
                    index = bytes;

                    for(i = 0; i < kptr->res_len; i++){
                        if(kptr->res[i] < pos) continue;
                        dist = kptr->res[i] % PAGE - (index - bytes);
                        strncpy(temp, index, dist);
                        temp[dist] = '\0';
                        index += dist + kptr->old_len;
                        rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                        if(rc < 0){
                            rc = -EPERM;
                            printk("Write the hash key to header of output file reading failed!\n");
                            goto set_oldfs;
                        }

                    }
                    strncpy(temp, index, rest - (index - bytes));
                    temp[rest - (index - bytes)] = '\0';
                    rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                    if(rc < 0){
                        rc = -EPERM;
                        printk("Write the hash key to header of output file reading failed!\n");
                        goto set_oldfs;
                    }

                }

            }

        }
        if(kptr->flag == 2){/* replace pattern */
            char *index;
            int page_count = 1;
            int dist = 0;
            while((inputInodeSize - readFilePtr->f_pos) > 0){
                if(inputInodeSize - readFilePtr->f_pos >= PAGE){
                    int pos = readFilePtr->f_pos;
                    dist = 0;

                    rc = readFilePtr->f_op->read(readFilePtr, bytes, PAGE, &readFilePtr->f_pos);
                    if(rc < 0){
                        rc = -EPERM;
                        printk("Read Blocks failed!\n");
                        goto set_oldfs;
                    }
                    bytes[PAGE] = '\0';
                    index = bytes;

                    for(i = 0; i < kptr->res_len; i++){
                        if(kptr->res[i] < pos) continue;
                        if(kptr->res[i] > page_count * PAGE) continue;
                        dist = kptr->res[i] % PAGE - (index - bytes);
                        strncpy(temp, index, dist);
                        temp[dist] = '\0';
                        index += dist + kptr->old_len;
                        rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                        if(rc < 0){
                            rc = -EPERM;
                            printk("Write the hash key to header of output file reading failed!\n");
                            goto set_oldfs;
                        }

                        strncpy(temp, kptr->new_str, kptr->new_len);
                        temp[kptr->new_len] = '\0';
                        rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                        if(rc < 0){
                            rc = -EPERM;
                            printk("Write the hash key to header of output file reading failed!\n");
                            goto set_oldfs;
                        }

                    }
                    strncpy(temp, index, PAGE - (index - bytes));
                    temp[PAGE - (index - bytes)] = '\0';
                    rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                    if(rc < 0){
                        rc = -EPERM;
                        printk("Write the hash key to header of output file reading failed!\n");
                        goto set_oldfs;
                    }	
                    page_count++;				

                }else{
                    int rest = inputInodeSize - readFilePtr->f_pos;
                    int pos = readFilePtr->f_pos;
                    dist = 0;
                    rc = readFilePtr->f_op->read(readFilePtr, bytes, rest, &readFilePtr->f_pos);
                    if(rc < 0){
                        rc = -EPERM;
                        printk("Read Blocks failed!\n");
                        goto set_oldfs;
                    }
                    bytes[rest] = '\0';
                    index = bytes;

                    for(i = 0; i < kptr->res_len; i++){
                        if(kptr->res[i] < pos) continue;
                        dist = kptr->res[i] % PAGE - (index - bytes);
                        strncpy(temp, index, dist);
                        temp[dist] = '\0';
                        index += dist + kptr->old_len;
                        rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                        if(rc < 0){
                            rc = -EPERM;
                            printk("Write the hash key to header of output file reading failed!\n");
                            goto set_oldfs;
                        }
                        strncpy(temp, kptr->new_str, kptr->new_len);
                        temp[kptr->new_len] = '\0';
                        rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                        if(rc < 0){
                            rc = -EPERM;
                            printk("Write the hash key to header of output file reading failed!\n");
                            goto set_oldfs;
                        }

                    }
                    strncpy(temp, index, rest - (index - bytes));
                    temp[rest - (index - bytes)] = '\0';
                    rc = writeFilePtr->f_op->write(writeFilePtr, temp ,strlen(temp), &writeFilePtr->f_pos);
                    if(rc < 0){
                        rc = -EPERM;
                        printk("Write the hash key to header of output file reading failed!\n");
                        goto set_oldfs;
                    }

                }

            }

        }

        /*goto mode 1 to write back*/
        rc = write_pat(kptr, 1);
    }

    if(mode == 1){/*write temp to new file*/
        while((inputInodeSize - readFilePtr->f_pos) > 0){
            if(inputInodeSize - readFilePtr->f_pos >= PAGE){
                rc = readFilePtr->f_op->read(readFilePtr, bytes, PAGE, &readFilePtr->f_pos);
                if(rc < 0){
                    rc = -EPERM;
                    printk("Read Blocks failed!\n");
                    goto set_oldfs;
                }
                bytes[PAGE] = '\0';

                rc = writeFilePtr->f_op->write(writeFilePtr, bytes ,PAGE, &writeFilePtr->f_pos);
                if(rc < 0){
                    rc = -EPERM;
                    printk("Write the hash key to header of output file reading failed!\n");
                    goto set_oldfs;
                }				
            }else{
                int rest = inputInodeSize - readFilePtr->f_pos;
                rc = readFilePtr->f_op->read(readFilePtr, bytes, rest, &readFilePtr->f_pos);
                if(rc < 0){
                    rc = -EPERM;
                    printk("Read Blocks failed!\n");
                    goto set_oldfs;
                }
                bytes[rest] = '\0';
                rc = writeFilePtr->f_op->write(writeFilePtr, bytes ,rest, &writeFilePtr->f_pos);
                if(rc < 0){
                    rc = -EPERM;
                    printk("Write the hash key to header of output file reading failed!\n");
                    goto set_oldfs;
                }

            }
        }
        if(kptr->flag == 1){printk("Deletion Succeed!\n"); kptr->flag = -1;}
        if(kptr->flag == 2){printk("Replacement Succeed!\n");kptr->flag = -2;}


        if ((rc = vfs_unlink(readFilePtr->f_path.dentry->d_parent->d_inode, readFilePtr->f_path.dentry, NULL)) < 0)
            printk("vfs_unlink failed\n");
    }

 set_oldfs:
    set_fs(oldfs);
    kfree(temp);
 free_bytes:
    kfree(bytes);
 close_output_file:
    filp_close(writeFilePtr, NULL);
 close_input_file:
    filp_close(readFilePtr, NULL);

 out:
    return rc;
}

/*check input file valid or not */
int isInFileValid(struct file *readFilePtr){
    int rc = 0;
    struct inode *inputIn = NULL;/*for get inode of input file*/
    size_t inputInodeSize = 0;/* for get size of input file*/
    umode_t inputInodeMode = 0;/*for get mode of input file*/

    /*check whether has read permission:		*/
    if(!readFilePtr->f_op->read){
        printk("Read input file Permission Denied!\n");
        rc = -EPERM;
        goto out;
    }
    /*get input file size and check whether null */
    inputIn = readFilePtr->f_path.dentry->d_inode;
    inputInodeSize = i_size_read(inputIn);

    if(inputInodeSize <= 0){
        printk("Error: input file's size is %zu\n",inputInodeSize);
        rc = -EPERM;
        goto out;
    }
    /*check whether input file is regular*/
    inputInodeMode = inputIn->i_mode;
    if(S_ISREG(inputInodeMode) == 0){
        printk("Error: The file is not regular: input file.\n");
        rc = -EISDIR;
        goto out;
    }
 out:
    return rc;
}

/*check output file valid or not*/
int isOutFileValid(struct file *writeFilePtr){
    int rc = 0;
    struct inode *outputIn = NULL;/*for get inode of output file*/
    umode_t outputInodeMode = 0;/*for get mode of output file*/

    /*check whether could be write*/
    if(!writeFilePtr->f_op->write){
        printk("Read output file Permission Denied!\n");
        rc = -EPERM;
        goto out;
    }
    /*check regularity of the output file*/
    outputIn = writeFilePtr->f_path.dentry->d_inode;
    outputInodeMode = outputIn->i_mode;
    if(S_ISREG(outputInodeMode) == 0){
        printk("Error: The file is not regular: output file.\n");
        rc = -EISDIR;
        goto out;
    }
 out:
    return rc;
}

/*
  isInputValid function accepts struct myargs as argument, 
  checks whether the inputs are legal, including non-null checking,
  match checking, same file checking, etc.
  The function will return error number if any error occurs, 0 if not.
*/
int isInputValid(void *arg){
    struct strops_args *ptr = (struct strops_args *)arg;

    if(ptr == NULL || ptr->in_file == NULL || ptr->old_len == 0 ||
       ptr->old_str == NULL)
        return -EFAULT;

    if(ptr->old_len > MAX_STR || ptr->new_len > MAX_STR)
        return -EINVAL;

    /*limit file path no longer than 512*/
    if(strlen(ptr->in_file) > 512)
        return -ENAMETOOLONG;

    return 0;
}
