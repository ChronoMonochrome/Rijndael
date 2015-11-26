class aes
{
public:
int static AES_do_crypt_from_file(char *infile, char *outfile, unsigned long *AES_key);
int static AES_do_decrypt_from_file(char *infile, char *outfile, unsigned long *AES_key);
};
