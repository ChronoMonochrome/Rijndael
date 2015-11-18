#define DEBUG 1
#define BUFSIZE 4 * 1024

int strlen(char*);


int RSA_do_public_encrypt(char * data, unsigned int data_len, unsigned char * key, char *encrypted);
int RSA_do_private_decrypt(char * enc_data, unsigned int data_len, unsigned char * key,  char *decrypted);
void printLastError(char *msg);

int AES_do_crypt_from_file(char *infile, char *outfile, char *iv);
int AES_do_decrypt_from_file(char *infile, char *outfile, char *iv);
