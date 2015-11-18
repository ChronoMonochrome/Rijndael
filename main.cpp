#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <ctime>

#include "private/misc.h"
#include "private/aes.h"
#include "rsa.h"
 

unsigned char iv[8];

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

int readFromFile(char *infile, unsigned char *inbuf, int start, int inbuf_len)
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

int writeToFile(char *outfile, unsigned char *outbuf, int outbuf_len)
{
        FILE *out = fopen(outfile, "w");
	int outlen = fwrite(outbuf, 1, outbuf_len, out);
	fclose(out);

	return outlen;
}

void RSA_do_encrypt_from_file(char *infile, char *outfile, char *pubKey)
{
        cryptkey publicKey;
        publicKey.loadFromFile(pubKey);
        rsa::encryptTxtFile(infile, outfile, publicKey);
}

void RSA_do_decrypt_from_file(char *infile, char *outfile, char *privKey)
{
        cryptkey privateKey;
        privateKey.loadFromFile(privKey);
        rsa::decryptTxtFile(infile, outfile, privateKey);
}

void encrypt(char *infile, char *outfile, char *pubKey)
{
	int i;
	int len;
	int inlen;
	unsigned char *encrypted_iv;
	unsigned char *decrypted_iv;
	unsigned char *buf;
	encrypted_iv = (unsigned char *)malloc(BUFSIZE);
	decrypted_iv = (unsigned char *)malloc(BUFSIZE);
	buf = (unsigned char *)malloc(BUFSIZE);


	srand(time(0));
	RAND_bytes(iv, 8);

	// cipher
	writeToFile("iv.txt", iv, 8);
	RSA_do_encrypt_from_file("iv.txt", "encrypted_iv.txt", pubKey);
	len = readFromFile("encrypted_iv.txt", encrypted_iv, 0, BUFSIZE);
	FILE *encrypted = fopen(outfile, "w+");
	fwrite(&len, sizeof(int), 1, encrypted);
	fwrite(encrypted_iv, len, 1, encrypted);

	printf("creating AES_cipher.txt\n");
	AES_do_crypt_from_file(infile, "AES_cipher.txt", iv);
	
	printf("creating RSA_AES_cipher.txt\n");
	RSA_do_encrypt_from_file("AES_cipher.txt", "RSA_AES_cipher.txt", "public_key");
	remove("AES_cipher.txt");
	
	FILE *RSA_AES_cipher = fopen("RSA_AES_cipher.txt", "r");
	for(;;) {
                inlen = fread(buf, 1, BUFSIZE, RSA_AES_cipher);
                if(inlen <= 0) break;
                fwrite(buf, 1, inlen, encrypted);
        }
	fclose(encrypted);
	fclose(RSA_AES_cipher);
 	remove("RSA_AES_cipher.txt");
 	remove("iv.txt");
 	remove("encrypted_iv.txt");

	free(buf);
	free(decrypted_iv);
	free(encrypted_iv);
}

void decrypt(char *infile, char *outfile, char *privKey)
{
	int i;
	int len, len1;
	int inlen, outlen;
	unsigned char *encrypted_iv;
	unsigned char *decrypted_iv;
	unsigned char *buf;
	encrypted_iv = (unsigned char *)malloc(BUFSIZE);
	decrypted_iv = (unsigned char *)malloc(BUFSIZE);
	buf = (unsigned char *)malloc(BUFSIZE);

	// decipher
	printf("creating iv\n");
	FILE *encrypted = fopen(infile, "r");
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

	RSA_do_decrypt_from_file("encrypted_iv.txt", "decrypted_iv.txt", privKey);
	readFromFile("decrypted_iv.txt", decrypted_iv, 0, len);
	remove("encrypted_iv.txt");
	remove("decrypted_iv.txt");

	RSA_do_decrypt_from_file("encrypted_message.txt", "decrypted_RSA_AES_cipher.txt", privKey);
	remove("encrypted_message.txt");
	printf("creating decrypted_message.txt\n");
	AES_do_decrypt_from_file("decrypted_RSA_AES_cipher.txt", outfile, decrypted_iv);

	remove("decrypted_RSA_AES_cipher.txt");

	free(buf);
	free(encrypted_iv);
	free(decrypted_iv);
}

int main(int argc, char *argv[])
{
	encrypt("orig.txt", "encrypted.txt", "public_key");
	decrypt("encrypted.txt", "encrypted_message.txt", "private_key");
	return 0;
}
 
