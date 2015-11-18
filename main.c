#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
 
#define DEBUG 1

int strlen(char*);
 
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

int RAND_bytes(unsigned char *buf, int num);

unsigned char key[32] = { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54,
        0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5 }; /* 256-битный ключ AES256*/
unsigned char iv[9]; /* вектор инициализации */


#define BUFSIZE 1024 * 4

int AES_do_crypt_from_file(char *infile, char *outfile, char *iv)
{
	int outlen, inlen;
	FILE *in, *out;
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER * cipher;

	in = fopen(infile, "r");
	out = fopen(outfile, "w");

	/* Обнуляем структуру контекста */
	EVP_CIPHER_CTX_init(&ctx);

	/* Выбираем алгоритм шифрования */
	cipher = EVP_aes_256_cfb();
 
	/* Инициализируем контекст алгоритма */
	EVP_EncryptInit(&ctx, cipher, iv, NULL);
 
	/* Шифруем данные */
	for(;;) {
		inlen = fread(inbuf, 1, BUFSIZE, in);
		if(inlen <= 0) break;
		if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) return 0;
		fwrite(outbuf, 1, outlen, out);
	}

	if(!EVP_EncryptFinal(&ctx, outbuf, &outlen))
		return 0;
	fwrite(outbuf, 1, outlen, out);
	EVP_CIPHER_CTX_cleanup(&ctx);
	fclose(in);
	fclose(out);
	return 1;
}

int AES_do_decrypt_from_file(char *infile, char *outfile, char *iv)
{
	int outlen, inlen;
	FILE *in, *out;
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER * cipher;

	in = fopen(infile, "r");
	out = fopen(outfile, "w");

	/* Обнуляем структуру контекста */
	EVP_CIPHER_CTX_init(&ctx);

	/* Выбираем алгоритм шифрования */
	cipher = EVP_aes_256_cfb();
 
	/* Инициализируем контекст алгоритма */
	EVP_DecryptInit(&ctx, cipher, iv, NULL);
 
	/* Шифруем данные */
	for(;;) {
		inlen = fread(inbuf, 1, BUFSIZE, in);
		if(inlen <= 0) break;
		if(!EVP_DecryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) return 0;
		fwrite(outbuf, 1, outlen, out);
	}

	if(!EVP_DecryptFinal(&ctx, outbuf, &outlen))
		return 0;
	fwrite(outbuf, 1, outlen, out);
	EVP_CIPHER_CTX_cleanup(&ctx);
	fclose(in);
	fclose(out);
	return 1;
}

char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
  
char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";

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


#define BUFSIZE 4 * 1024
int RSA_do_crypt_from_file(char *infile, char *outfile)
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
		//exit(0);
	}
	printf("Encrypted length =%d\n",encrypted_length);
	fwrite(outbuf, 1, encrypted_length, out);
fail:
	fclose(in);
	fclose(out);

	return encrypted_length;
}

void RSA_do_decrypt_from_file(char *infile, char *outfile)
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
		//exit(0);
	}
	printf("Encrypted length =%d\n",decrypted_length);
	fwrite(outbuf, 1, decrypted_length, out);
fail:
	fclose(in);
	fclose(out);
}

int readFromFile(char *infile, char *inbuf, int start, int inbuf_len)
{
        FILE *in = fopen(infile, "r");
	if (start > 0) {
		char tmp[start];
		fread(tmp, 1, start, in);
	}

	int inlen = fread(inbuf, 1, inbuf_len, in);
	fclose(in);

	return inlen;
}

int writeToFile(char *outfile, char *outbuf, int outbuf_len)
{
        FILE *out = fopen(outfile, "w");
	int outlen = fwrite(outbuf, 1, outbuf_len, out);
	fclose(out);

	return outlen;
}
 

int main(int argc, char *argv[])
{
	int i;
	int len, len1, inlen, outlen;
	unsigned char encrypted_iv[BUFSIZE]={};
	unsigned char decrypted_iv[BUFSIZE]={};
	unsigned char buf[BUFSIZE];
	RAND_bytes(iv, 8);
	
	// cipher
	len = RSA_do_crypt_source(iv, publicKey, encrypted_iv);
	FILE *encrypted = fopen("encrypted.txt", "w+");
	fwrite(&len, sizeof(int), 1, encrypted);
	fwrite(encrypted_iv, len, 1, encrypted);
	fclose(encrypted);

	//writeToFile("encrypted_iv.txt", encrypted_iv, len);
	printf("creating AES_cipher.txt\n");
	AES_do_crypt_from_file("orig.txt", "AES_cipher.txt", iv);
	
	printf("creating RSA_AES_cipher.txt\n");
	RSA_do_crypt_from_file("AES_cipher.txt", "RSA_AES_cipher.txt");
	remove("AES_cipher.txt");
	
	system("cat RSA_AES_cipher.txt >> encrypted.txt");
	remove("RSA_AES_cipher.txt");
	len = 0;
	
	// decipher
	printf("creating iv\n");
	encrypted = fopen("encrypted.txt", "r");
	fread(&len, sizeof(int), 1, encrypted);

	fread(encrypted_iv, len, 1, encrypted);
	writeToFile("encrypted_iv.txt", encrypted_iv, len);

	FILE *encrypted_message = fopen("encrypted_message.txt", "w+");
        for(;;) {
                inlen = fread(buf, 1, BUFSIZE, encrypted);
                if(inlen <= 0) break;
                fwrite(buf, 1, inlen, encrypted_message);
        }
	fclose(encrypted);
	fclose(encrypted_message);

	RSA_do_decrypt_from_file("encrypted_iv.txt", "decrypted_iv.txt");
	readFromFile("decrypted_iv.txt", decrypted_iv, 0, len);
	remove("encrypted_iv.txt");
	remove("decrypted_iv.txt");

	RSA_do_decrypt_from_file("encrypted_message.txt", "decrypted_RSA_AES_cipher.txt");
	remove("encrypted_message.txt");
	printf("creating decrypted_message.txt\n");
	AES_do_decrypt_from_file("decrypted_RSA_AES_cipher.txt", "decrypted_message.txt", decrypted_iv);
	//AES_do_decrypt_from_file("decrypted_RSA_AES_cipher1.txt", "decrypted_message1.txt", decrypted_iv);

	remove("decrypted_RSA_AES_cipher.txt");
	
	return 0;
}
 
