int RSA_do_public_encrypt(char * data, unsigned int data_len, unsigned char * key, char *encrypted);
int RSA_do_private_decrypt(char * enc_data, unsigned int data_len, unsigned char * key,  char *decrypted);
void printLastError(char *msg);

int RSA_do_crypt_source(char *plainText, char *publicKey, char *encrypted_plainText);
int RSA_do_decrypt_source(char *plainText, char *privateKey, char *decrypted_plainText);
int RSA_do_crypt_from_file(char *infile, char *outfile, char *publicKey);
void RSA_do_decrypt_from_file(char *infile, char *outfile, char *privateKey);
