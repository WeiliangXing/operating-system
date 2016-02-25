#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/hash.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include "encrypt.h"
#include "common.h"
#include "preamble.h"
#include "utils.h"

#define IS_ENC_MODE(x) (x->op == ENCRYPT)
#define IS_DEC_MODE(x) (x->op == DECRYPT)
#define CHUNK_SIZE PAGE_SIZE

int get_md5(char *key, char * digest, int string);
int check_filetype(struct file *filp);
char *make_tmp_outfilename(const char *src);
void print_nomem(char *name);
int get_file_size(char *filename, int *sz);
void print_dump(void *buf, int sz);
int write_file2(struct file *filp, void *buf, int count);
int unlink_file_if_needed(const char *filename);
int read_file(struct file *filp, void *buf, int count);
int rename_from_tmp2(const char *tmp, const char *dst);
int rename_wrapper2(struct path lower_old_path, struct path lower_new_path);

/*main function to encryption*/
int hw3_encrypt(struct kjob_info* job) {
    struct encrypt_args* e_args = NULL;
    struct file* fpin = NULL;
    struct file* fpout = NULL;
    struct scatterlist sg_in[2], sg_out[1];
    struct crypto_blkcipher *tfm = NULL;
    struct blkcipher_desc cphdesc;
    void *rd_buf = NULL;
    void *wrt_buf = NULL;
    void *src_chunk = NULL;
    void *dst_chunk = NULL;
    void *leftover_buf = NULL;
    xcr_preamble* preamble = NULL;
    char* cipher = NULL;
    char* tmp_outfile = NULL;
    char md5_hash[16];
    int res = 0, keylen = 16, block_len = 0, key_sz = 0, input_file_sz = 0, bytes_total_read = 0, bytes = 0,pg_offset = 0, 
        wr_offset = 0, chunk_sz = 0, leftover_sz = 0, cres = 0;
    
    memset(md5_hash, 0, 16);
    e_args = job->opts;

    if(e_args->cipher_type == AES) {
        cipher = kmalloc(strlen("cbc(aes)") + 1, GFP_KERNEL);
        strcpy(cipher, "cbc(aes)");
        printk("Cipher: AES    \n");
        block_len = 16;
    }
    else if(e_args->cipher_type == BLOWFISH){
        cipher = kmalloc(strlen("cbc(blowfish)") + 1, GFP_KERNEL);
        strcpy(cipher, "cbc(blowfish)");
        printk("Cipher: Blowfish \n");
        block_len = 8;
    }
    if(!cipher){
        UDBG;
        res = -ENOMEM;
        goto freeMem;
    }
        
    /*try to open the file */
    fpin = filp_open(job->filename, O_RDONLY, 0);
    if (!fpin || IS_ERR(fpin)) {
        printk("Read file error: %d\n", (int)PTR_ERR(fpin));
        res = PTR_ERR(fpin);
        goto freeMem;
    }    
    
    if ((res = check_filetype(fpin)) != 0) {
        switch (res) {
        case -EISDIR:
            printk("The input file cannot be a directory\n");
            goto freeMem;
        default:
            printk("The name is not a file at all\n");
            goto freeMem;
        }
    }
    
    if (!fpin->f_op->read) {
        printk("File system doesn't allow reads\n");
        res = -EACCES;
        goto freeMem;
    }
    
    tmp_outfile = make_tmp_outfilename(job->outfilename);
    if (!tmp_outfile) {
        UDBG;
        res = -ENOMEM;
        goto freeMem;
    }
    
    /*open the outfile */
    fpout = filp_open(tmp_outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (!fpout || IS_ERR(fpout)) {
        printk("Bad open of output file: %d\n", (int)PTR_ERR(fpout));
        res = PTR_ERR(fpout);
        if (res == -EISDIR) 
            printk("The output file cannot be a directory\n");
        goto freeMem;
    }

    if (!fpout->f_op->write) {
        printk("File system doesn't allow writes\n");
        res = -EACCES;
        goto freeMem;
    }
    
    /*prepare to read from infile, write to outfile */
    fpin->f_pos = 0;
    fpout->f_pos = 0;    
    
    sg_init_table(sg_in, 1);
    sg_init_table(sg_out, 1);        
    
    tfm = crypto_alloc_blkcipher(cipher, 0, 0);
    if (IS_ERR(tfm)) {
        printk("Cannot create tfm for selected cipher\n");
        res = -EINVAL;
        goto freeMem;
    }
    
    get_md5(e_args->key, md5_hash, 1);
    crypto_blkcipher_setkey(tfm, md5_hash, keylen);    

    if (IS_ENC_MODE(e_args)) {
        preamble = prmb_create(md5_hash, 16);
        if (IS_ERR(preamble)) {
            printk("Error when building a preamble\n");
            goto freeMem;
        }
        
        prmb_save(preamble, fpout);
    }

    else if(IS_DEC_MODE(e_args)){
        preamble = kmalloc(sizeof(xcr_preamble), GFP_KERNEL);
        preamble->hashbuf = NULL;
        
        if ((res = prmb_load(preamble, fpin)) != 0){
            goto freeMem;
        }
        
        if ((res = prmb_check_key(preamble, md5_hash, keylen)) != 0) {
            if (res == -EPERM)
                printk("Wrong password\n");
            goto freeMem;
        }
    }
    
    rd_buf = kmalloc((int)CHUNK_SIZE, GFP_KERNEL);
    wrt_buf = kmalloc(CHUNK_SIZE, GFP_KERNEL);
    key_sz = block_len;
    src_chunk = kmalloc(key_sz, GFP_KERNEL);
    dst_chunk = kmalloc(key_sz, GFP_KERNEL);
    leftover_buf = kmalloc(key_sz, GFP_KERNEL);
    if (!rd_buf || !wrt_buf || !src_chunk || !dst_chunk || !leftover_buf) {
        print_nomem("one of the buffers(s) for reading, writing, encryption, decryption, leftover\0");
        res = -ENOMEM;
        goto freeMem;
    }
    
    cphdesc.tfm = tfm;
    cphdesc.flags = 0;
    sg_set_buf(&sg_in[0], src_chunk, key_sz);
    sg_set_buf(sg_out, dst_chunk, key_sz);        

    if(!fpin->f_inode->i_size){
        printk("Can't get file size or input file is 0 bytes \n");
        goto freeMem;
    }
    
    input_file_sz = fpin->f_inode->i_size;
    printk("filesize %d \n", input_file_sz);
    if (IS_DEC_MODE(e_args))
        input_file_sz -= PRMB_SZ;

    bytes_total_read = 0;
    while(1) { /* read/write loop */
        memset(rd_buf, 0, CHUNK_SIZE);
        memset(wrt_buf, 0, CHUNK_SIZE);

        bytes = read_file(fpin, rd_buf, (int)CHUNK_SIZE);
        bytes_total_read += bytes;
        if (bytes < 0) {
            printk("Error during reading file\n");
            res = -EFAULT;
            goto freeMem;
        } else if (bytes == 0)
            break;
        printk("Read %d bytes, fpos=%d\n", bytes, (int)fpin->f_pos);

        pg_offset = 0;
        wr_offset = 0;
        chunk_sz = 0;

        while(1) { /*enc/dec loop */
            memset(src_chunk, 0, key_sz);
            memset(dst_chunk, 0, key_sz);            

            if (bytes < CHUNK_SIZE && pg_offset == 0) {        
        if (IS_ENC_MODE(e_args)) {
            if ((res = prmb_pad_buf(preamble, rd_buf, bytes, key_sz, leftover_sz)) != 0)            
                goto freeMem;
            
            if ((res = prmb_save_pad(preamble, fpout)) != 0) {
                goto freeMem;
            }
        }
            }
            /* now we have to copy keylen bytes from rd_buf into src_chunk to encr/decr them, but not enough! */
            /* So save them into leftover */
            else if ((pg_offset + key_sz) > CHUNK_SIZE) {
        leftover_sz = CHUNK_SIZE - pg_offset;
        printk("Saving leftover,offset=%d, leftoversize=%d, chunksize=%d\n", pg_offset, leftover_sz, chunk_sz);
        memcpy(leftover_buf, rd_buf + pg_offset, leftover_sz);        
        break;
            }

            if (leftover_sz == 0) {
        memcpy(src_chunk, rd_buf + pg_offset, key_sz);
        chunk_sz += key_sz;
        printk("Copied %d bytes to src_chunk, offset=%d,chunk_sz=%d\n", key_sz, pg_offset, chunk_sz);
        printk("src_chunk:");
        print_dump(src_chunk, key_sz);        
            } else {
        memcpy(src_chunk, leftover_buf, leftover_sz);
        chunk_sz += leftover_sz;
        printk("Copied %d bytes to src_chunk from leftover, chunk_sz=%d\n", leftover_sz, chunk_sz);
        printk("src_chunk:");
        print_dump(src_chunk, chunk_sz);
        
        memcpy((void *)(src_chunk + leftover_sz), rd_buf, key_sz - leftover_sz);
        chunk_sz += (key_sz - leftover_sz);
        printk("Copied %d bytes to src_chunk, offset=%d, chunk_sz=%d\n", key_sz - leftover_sz, pg_offset, chunk_sz);
        printk("src_chunk:");
        print_dump(src_chunk, chunk_sz);
            }
            
            if (IS_ENC_MODE(e_args)) {
        cres = crypto_blkcipher_encrypt(&cphdesc, sg_out, sg_in, key_sz);
        if (cres) {
            res = -EFAULT;
            printk("Can't encrypt\n");
            goto freeMem;
        }
            } else if (IS_DEC_MODE(e_args)) {
        cres = crypto_blkcipher_decrypt(&cphdesc, sg_out, sg_in, key_sz);
        if (cres) {
            res = -EFAULT;
            printk("Can't decrypt\n");
            goto freeMem;
        }
            }
            printk("Encrypted\n");

            memcpy(wrt_buf + wr_offset, dst_chunk, key_sz);            
            printk("Copied %d bytes to writebuf, offset=%d\n", key_sz, pg_offset);
            printk("pg_offset was:%d", pg_offset);
            pg_offset += (key_sz - leftover_sz);
            wr_offset += key_sz; /* an offset for write always icnrements by key size */
            printk(", became:%d\n\n", pg_offset);
            leftover_sz = 0;

            if (IS_ENC_MODE(e_args) && pg_offset == bytes + preamble->padding) {
        printk("EOF reached\n");
        break; /* EOF reached */
            } else if (IS_DEC_MODE(e_args) && pg_offset == bytes) {
        printk("EOF reached\n");
        break; /* EOF reached */
            }
        } /*encr/decr loop */

        printk("Going to write to file, total read=%d, sz=%d, padding=%d, chunk_sz=%d\n", bytes_total_read, input_file_sz, preamble->padding, chunk_sz);
        if (IS_DEC_MODE(e_args) && bytes_total_read == input_file_sz) {
            /* remove padding from decrypted last part */
            write_file2(fpout, wrt_buf, chunk_sz - preamble->padding);
            printk("Write to file w/o padding, chunk_sz=%d,padding=%d\n", chunk_sz, preamble->padding);
        } else {        
            /* write not how much you read, but how much you advanced */
            /* chunk_sz is a sum of all buffers sizes you read from the time of last file read (including leftover buf) */    
            write_file2(fpout, wrt_buf, chunk_sz);
            printk("Write to file %d bytes\n\n", chunk_sz);
        }

        if (bytes < CHUNK_SIZE)
            break;            
    } /*read/write loop */

    if (fpout && !IS_ERR(fpout)) {
        filp_close(fpout, NULL);
        fpout = NULL;
    }

    printk("Renaming from %s to %s\n", tmp_outfile, job->outfilename);
    if ((res = rename_from_tmp2(tmp_outfile, job->outfilename))){
        printk("Cannot rename tmp file to %s\n", job->outfilename);
        goto freeMem;
    }

/*free memory if allocated */
freeMem:

    unlink_file_if_needed(tmp_outfile);
    if(cipher)
        kfree(cipher);
    if(e_args)
        kfree(e_args);
    if (fpin && !IS_ERR(fpin))
        filp_close(fpin, NULL);    
    if (fpout && !IS_ERR(fpout))
        filp_close(fpout, NULL);
    if (tfm)
        crypto_free_blkcipher(tfm);    
    if (rd_buf)
        kfree(rd_buf);
    if (wrt_buf)
        kfree(wrt_buf);    
    if (preamble) {
        if (preamble->hashbuf)
            kfree(preamble->hashbuf);
        kfree(preamble);
    }
    if (tmp_outfile)
        kfree(tmp_outfile);
    if (src_chunk)
        kfree(src_chunk);
    if (dst_chunk)
        kfree(dst_chunk);

    return res;
}

/*function to free encryption option struct*/
void
free_encrypt_ops(struct kjob_info *job) {
        struct encrypt_args* opts;
        if (!job) return;
        if (!job->opts) return;
        
        opts = (struct encrypt_args *)job->opts;
        if (opts->key)
                kfree(opts->key);
        
        kfree(job->opts);
        job->opts = NULL;
}

/*copy encrypt option from user to kernel*/
int kcopy_encrypt_info(struct kjob_info *dst, struct kjob_info *src) {
        struct encrypt_args *dopts = NULL, *sopts = NULL;
        int rc = 0;
        
        if (!(dst->opts = kmalloc(sizeof(struct encrypt_args), GFP_KERNEL))) {
                rc = -ENOMEM;
                goto errout;
        }
        
        dopts = (struct encrypt_args *)dst->opts;
        sopts = (struct encrypt_args *)src->opts;
        
        memcpy(dopts, sopts, sizeof(struct encrypt_args));
        
        if(!(dopts->key = kstrdup(sopts->key, GFP_KERNEL))){
                rc = -ENOMEM;
                goto errout;
        }
        
errout:
        if(rc)
                free_encrypt_ops(dst);
        
        free_encrypt_ops(src);
        return rc;    

}

/* copy encryption struct from user to kernel*/
int copy_encrypt_struct(struct kjob_info *kjob, struct kjob_info __user *ujob) {
        struct encrypt_args* kopts = NULL;
	struct encrypt_args* uopts = NULL;
        int rc = 0;


        /* Error check */
        if (!ujob || !kjob->opts) /* an indirect check of ujob->opts */
                return -EFAULT;
 
        kjob->opts = kmalloc(sizeof(struct encrypt_args), GFP_KERNEL);
        if (!kjob->opts) {
                rc = -ENOMEM;
                goto errout;
        }
        
        kopts = (struct encrypt_args *)kjob->opts;
        uopts = (struct encrypt_args *)ujob->opts;
        
        if (copy_from_user(kopts, uopts, sizeof(struct encrypt_args))) {
                rc = -EFAULT;
                goto errout;
        }
                
        if(copy_user_str(&kopts->key, uopts->key)){
                rc = -ENOMEM;
                goto errout;
        }       
        
        if(rc == 0)
                return rc;
        
errout:
        if(kopts)
                kfree(kopts);
        if(kopts->key)
                kfree(kopts->key);

        return rc;
}

/*compute hash of key*/
int
get_md5(char *key, char * digest, int string)
{

    struct crypto_shash *hash = NULL;
    struct shash_desc* sdesc = NULL;
    char * hash_type = "md5";
    int err = 0, size=0;

    memset(digest, 0, 16);
    hash = crypto_alloc_shash(hash_type, 0, 0);
    if(IS_ERR(hash)){
        printk("Could not allocate hash \n");
        err = -PTR_ERR(hash);
        goto out;
    }    

    size = sizeof(struct shash_desc) + crypto_shash_descsize(hash);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc){
        err = -ENOMEM;
        goto out;
    }

    sdesc->tfm = hash;
    sdesc->flags = 0x0;

    if (string)
        err    = crypto_shash_digest(sdesc, key, strlen(key), digest);
    else
        err = crypto_shash_digest(sdesc, key, 16, digest);

 out:
    if(hash)
        crypto_free_shash(hash);
    if(sdesc)
        kfree(sdesc);

    return err;
}

/*PREAMBLE FUNCTIONS*/
int prmb_save(xcr_preamble* preamble, struct file *filp) {
    int bytes = 0;
    if (!preamble || !preamble->hashbuf || !filp) {
        return -EINVAL;
    }

    /* 1. write length of hashbuf */
    bytes = write_file2(filp, &preamble->hashlen, sizeof(int));
    if (bytes != sizeof(int)){
        printk("Didn't write the part of preamble\n");
        return -EACCES;
    }

    /* 2. write the hashed buffer */
    bytes = write_file2(filp, preamble->hashbuf, preamble->hashlen);
    if (bytes != preamble->hashlen){
        printk("Didn't write the part of preamble\n");
        return -EACCES;
    }

    bytes = write_file2(filp, &preamble->padding, sizeof(int));
    if (bytes != sizeof(int)){
        printk("Didn't write padding into the preamble\n");
        return -EACCES;
    }
    
    return 0;
}

/*save pad*/
int prmb_save_pad(xcr_preamble* preamble, struct file *filp) {
    int bytes;
    int tmp_pos = filp->f_pos;
    filp->f_op->llseek(filp, 24, SEEK_SET);
    bytes = write_file2(filp, &preamble->padding, sizeof(int));
    if (bytes != sizeof(int)){
        printk("Didn't write padding into the preamble\n");
        return -EACCES;
        } 
    filp->f_op->llseek(filp, tmp_pos, SEEK_SET);
    return 0;
}
/*load preamble*/
int prmb_load(xcr_preamble* preamble, struct file *filp){
    int bytes = 0;    
    int res = 0;
    void* buf = NULL;
    char *err_not_prmb = "Cannot restore preamble. Most probably the file you're trying to decrypt is not an encrypted file\n";
    if (!preamble || !filp) {
        res = -EINVAL;
        goto prmbld_free;
    }

    buf = kmalloc(CHUNK_SIZE, GFP_KERNEL);
    memset(buf, 0, CHUNK_SIZE);

    bytes = read_file(filp, buf, sizeof(int));
    if (bytes < sizeof(int)){
        printk(err_not_prmb);
        res = -EINVAL;
        goto prmbld_free;
    }

    memcpy((void *)&preamble->hashlen, buf, sizeof(int));
    if (preamble->hashlen <= 0) {
        res = -EINVAL;
        goto prmbld_free;
    }

    memset(buf, 0, CHUNK_SIZE);
    bytes = read_file(filp, buf, preamble->hashlen);
    if (bytes < preamble->hashlen) {
        printk(err_not_prmb);
        res = -EINVAL;
        goto prmbld_free;
    }
    preamble->hashbuf = kmalloc(preamble->hashlen, GFP_KERNEL);
    memcpy(preamble->hashbuf, buf, preamble->hashlen);    

    bytes = read_file(filp, buf, sizeof(int));
    if (bytes < sizeof(int)){
        printk(err_not_prmb);
        res = -EINVAL;
        goto prmbld_free;
    }

    memcpy((void *)&preamble->padding, buf, sizeof(int));
    if (preamble->padding < 0) {
        res = -EINVAL;
        goto prmbld_free;
    }

    printk("Preamble is restored and fpos=%d\n", (int)filp->f_pos);
    
    prmbld_free:
    if (buf)
        kfree(buf);
    return res;
}


int prmb_pad_buf(xcr_preamble *preamble, void *buf, int bytes_read, int key_sz, int leftover_sz) {
    int pad_size;
    int data_len;
    if (leftover_sz)
        data_len = bytes_read - key_sz + leftover_sz;
    else
        data_len = bytes_read;
    if (!key_sz) {
        return -EINVAL;
    }
    pad_size = key_sz - data_len % key_sz;
    if (pad_size < 0) {
        return -EINVAL;
    }
    memset(buf + bytes_read, 0, pad_size);
    preamble->padding = pad_size;
    printk("Pad buf with %d bytes\n", pad_size);
    return 0;
}


xcr_preamble* prmb_create(unsigned char* keybuf, int keylen) {
    int res = 0;
    xcr_preamble* prmb = kmalloc(sizeof(xcr_preamble), GFP_KERNEL);

    if (!prmb)
        return ERR_PTR(-ENOMEM);
    prmb->hashbuf = kmalloc(HASH_LENGTH, GFP_KERNEL);
    if (!prmb->hashbuf)
        return ERR_PTR(-ENOMEM);

    if ((res = do_hash_sha1(keybuf, keylen, prmb->hashbuf))) {
        return ERR_PTR(res);
    }

    prmb->hashlen = HASH_LENGTH;
    prmb->padding = 0;
    return prmb;
}                                                                                                             

/*encypt using sha1*/
int do_hash_sha1(unsigned char* keybuf, int keylen, char *outputBuf) {
    struct crypto_hash *tfm;
    struct scatterlist sg;    
    struct hash_desc desc;    
    unsigned char hashed[20];

    if (!keybuf || !outputBuf || keylen <= 0) {
        return -EINVAL;
    }
    
    memset(hashed, 0, HASH_LENGTH);

    tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
        printk("Failed to load transform for SHA-1");
        return -ENOSYS;
    }

    desc.tfm = tfm;
    desc.flags = 0;

    sg_init_one(&sg, keybuf, keylen);
    crypto_hash_init(&desc);

    crypto_hash_update(&desc, &sg, keylen);
    crypto_hash_final(&desc, hashed);
    crypto_free_hash(tfm);

    memcpy(outputBuf, hashed, keylen);

    return 0;
}

/*check file type*/
int check_filetype(struct file *filp) {
    struct inode *inode = file_inode(filp);
    if (S_ISREG(inode->i_mode))
        return 0;
    if (S_ISDIR(inode->i_mode))
        return -EISDIR;
    return -ENOTTY;
}

/*check key*/
int prmb_check_key(xcr_preamble *preamble, unsigned char* key, int keylen) {
    int res = 0;
    char *hashbuf = kmalloc(HASH_LENGTH, GFP_KERNEL);
    if (!hashbuf) {
        res = -ENOMEM;
    }
    if (!preamble || !preamble->hashbuf || !key || keylen <= 0) {
        res = -EINVAL;
    }

    if ((res = do_hash_sha1(key, keylen, hashbuf))) {
        return res;
    }

    if (memcmp(preamble->hashbuf, hashbuf, HASH_LENGTH) == 0) {
        res = 0;
    } else
        res = -EPERM;
    return res;
}

void print_nomem(char *name) {
    printk("Cannot allocate a memory block for %s, abort\n", name);
}

int get_file_size(char *filename, int *sz) {
    struct kstat st;
    int res = 0;
    res = vfs_stat(filename, &st);
    *sz = (int)st.size;
    return res;
}

int read_file(struct file *filp, void *buf, int count) {
    mm_segment_t oldfs;
    int bytes;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    bytes = filp->f_op->read(filp, buf, count, &filp->f_pos);

    set_fs(oldfs);
    return bytes;
}

int write_file2(struct file *filp, void *buf, int count) {
    mm_segment_t oldfs;
    int bytes;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    bytes = filp->f_op->write(filp, buf, count, &filp->f_pos);

    set_fs(oldfs);
    return bytes;
}

void print_dump(void *buf, int sz) {
    int i;
    for(i=0;i<sz;++i)
        printk("%c", ((char*)buf)[i]);
    printk("\n");
}

int rename_from_tmp2(const char *tmp, const char *dst) {
    struct file *filp_old, *filp_new;
    struct inode *old_inode;
    struct dentry *old_dentry;
    struct inode *new_inode;
    struct dentry *new_dentry;
    
    int res = 0;
    
    if (!tmp || !dst)
        return -EINVAL;
    filp_old = filp_open(tmp, O_RDONLY, 0);
    if (!filp_old || IS_ERR(filp_old)){
        res = PTR_ERR(filp_old);
        return res;
    }
    filp_new = filp_open(dst, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (!filp_new || IS_ERR(filp_new)) {
        printk("Bad open of output file: %d\n", (int)PTR_ERR(filp_new));
        res = PTR_ERR(filp_new);
        BUG_ON(res == -EISDIR);            
        filp_close(filp_old, NULL);
        return res;
    }

    old_inode = file_inode(filp_old);
    old_dentry = filp_old->f_path.dentry;
    new_inode = file_inode(filp_new);
    new_dentry = filp_new->f_path.dentry;

    if ((res = rename_wrapper2(filp_old->f_path,filp_new->f_path))) {
        printk("Couldn't rename it\n");
    }

    filp_close(filp_old, NULL);
    filp_close(filp_new, NULL);
    return res;
}

int rename_wrapper2(struct path lower_old_path, struct path lower_new_path)
{
        int err = 0;
        struct dentry *lower_old_dentry = NULL;
        struct dentry *lower_new_dentry = NULL;
        struct dentry *lower_old_dir_dentry = NULL;
        struct dentry *lower_new_dir_dentry = NULL;
        struct dentry *trap = NULL;

        lower_old_dentry = lower_old_path.dentry;
        lower_new_dentry = lower_new_path.dentry;
        lower_old_dir_dentry = dget_parent(lower_old_dentry);
        lower_new_dir_dentry = dget_parent(lower_new_dentry);
        
        trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
        if (trap == lower_old_dentry) {
                        err = -EINVAL;
                        goto out;
        }
        if (trap == lower_new_dentry) {
                        err = -ENOTEMPTY;
                        goto out;
        }

        err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry, lower_new_dir_dentry->d_inode, lower_new_dentry, NULL, 0);
        if (err) {
            goto out;
        }
out:
        unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
        dput(lower_old_dir_dentry);
        dput(lower_new_dir_dentry);
        return err;
}

char *make_tmp_outfilename(const char *src) {
    int sfxlen = 4;
    char *dst = (char *)kmalloc(strlen(src) + sfxlen + 1, GFP_KERNEL);
    memset(dst, 0, strlen(src) + sfxlen + 1);
    if (!dst)
        return NULL;
    memcpy(dst, src, strlen(src));    
    memcpy((dst + strlen(src)), ".tmp", sfxlen);
    return dst;
}

int unlink_file_if_needed(const char *filename) {
    int res = 0;
    struct file* filp = NULL;
    struct kstat stat;
    struct inode *ind;

    if ((res = vfs_stat(filename, &stat)) == -ENOENT) {
        printk("No need in unlinking tmp file\n");
        return 0;
    }

    filp = filp_open(filename, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)){
        res = PTR_ERR(filp);
        return res;
    }
    ind = dget_parent(filp->f_path.dentry)->d_inode;
    res = vfs_unlink(ind, filp->f_path.dentry, NULL);
    if (res == -EWOULDBLOCK) {
        printk("A delegation is found when unlinking\n");
    }

    filp_close(filp, NULL);
    return res;
}

