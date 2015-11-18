#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
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
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
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
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

