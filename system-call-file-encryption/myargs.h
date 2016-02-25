typedef struct myargs{//structure to hold all arg
  char *passwdBuf;//buffer for password
  size_t passwdLen;//len of password buffer
  char *inFile;//input fileName
  char *outFile;//output fileName
  int flag;//Encrpt: LSB-0, Decrpt: LSB-1
} myargs;

