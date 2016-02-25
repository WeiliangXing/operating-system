#ifndef PREAMBLE_H
#define PREAMBLE_H

struct Xcr_preamble {
  unsigned char* hashbuf;
  int hashlen;
  
  int len;
  int padding;
};

typedef struct Xcr_preamble xcr_preamble;

/* sets pointers, not allocates */
xcr_preamble* prmb_create(unsigned char* keybuf, int keylen);
int prmb_save(xcr_preamble* preamble, struct file *filp);
int prmb_save_pad(xcr_preamble* preamble, struct file *filp);
int prmb_load(xcr_preamble* preamble, struct file *filp);
int prmb_check_key(xcr_preamble *preamble, unsigned char* key, int keylen);
/* allocate 20 bytes for outputBuf before calling */
int do_hash_sha1(unsigned char* keybuf, int keylen, char *outputBuf);
int prmb_pad_buf(xcr_preamble *preamble, void *buf, int bytes_read, int key_sz, int leftover_sz);

#define HASH_LENGTH 20
#define PRMB_SZ 28

#endif
