#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

#include "private/misc.h"

int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key, int public)
{
    RSA *rsa= NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
 
    if (!keybio)
    {
        printf( "Failed to create key BIO");
        return 0;
    }

    if(public)
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    else
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);

    if (!rsa)
        printf( "Failed to create RSA");
 
    return rsa;
}
 
int RSA_do_public_encrypt(char * data, unsigned int data_len, unsigned char * key, char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

int RSA_do_private_decrypt(char * enc_data, unsigned int data_len, unsigned char * key,  char *decrypted)
{
    RSA * rsa = createRSA(key, 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}
 
int RSA_do_private_encrypt( char * data, unsigned int data_len, unsigned char * key,  char *encrypted)
{
    RSA * rsa = createRSA(key, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}
int RSA_do_public_decrypt( char * enc_data, unsigned int data_len, unsigned char * key,  char *decrypted)
{
    RSA * rsa = createRSA(key, 1);
    int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

int RSA_do_crypt_source(char *plainText, char *publicKey, char *encrypted_plainText)
{
	int encrypted_length = RSA_do_public_encrypt(plainText, strlen(plainText), publicKey, encrypted_plainText);
#ifdef DEBUG
	if (encrypted_length < 0)
		printLastError("Public Encrypt failed ");

	printf("Encrypted length =%d\n",encrypted_length);
#endif

	return encrypted_length;
}

int RSA_do_decrypt_source(char *plainText, char *privateKey, char *decrypted_plainText)
{

	int decrypted_length = RSA_do_private_decrypt(plainText, strlen(plainText), privateKey, decrypted_plainText);
#ifdef DEBUG
	if (decrypted_length < 0)
		printLastError("Private Decrypt failed ");

	printf("Decrypted length =%d\n", decrypted_length);
#endif
	
	return decrypted_length;
}


int RSA_do_crypt_from_file(char *infile, char *outfile, char *publicKey)
{

	int outlen, inlen;
	FILE *in, *out;
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
 
	in = fopen(infile, "r");
	out = fopen(outfile, "w");
	inlen = fread(inbuf, 1, BUFSIZE, in);
 
	int encrypted_length = RSA_do_public_encrypt(inbuf, inlen, publicKey, outbuf);
	if(encrypted_length == -1)
	{
		printLastError("Public Encrypt failed ");
		goto fail;
	}
	printf("Encrypted length =%d\n",encrypted_length);
	fwrite(outbuf, 1, encrypted_length, out);
fail:
	fclose(in);
	fclose(out);

	return encrypted_length;
}

void RSA_do_decrypt_from_file(char *infile, char *outfile, char *privateKey)
{

	int outlen, inlen;
	FILE *in, *out;
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];

	in = fopen(infile, "r");
	out = fopen(outfile, "w");
	inlen = fread(inbuf, 1, BUFSIZE, in);

	int decrypted_length = RSA_do_private_decrypt(inbuf, inlen, privateKey, outbuf);
	if(decrypted_length == -1)
	{
		printLastError("Public Encrypt failed ");
		goto fail;
	}
	printf("Encrypted length =%d\n",decrypted_length);
	fwrite(outbuf, 1, decrypted_length, out);
fail:
	fclose(in);
	fclose(out);
}

