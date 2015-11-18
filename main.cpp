#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>

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

void encrypt(char *infile, char *outfile, char *pubKey)
{
        cryptkey publicKey;
        publicKey.loadFromFile(pubKey);
        rsa::encryptTxtFile(infile, outfile, publicKey);
}

void decrypt(char *infile, char *outfile, char *privKey)
{
        cryptkey privateKey;

        privateKey.loadFromFile(privKey);

        rsa::decryptTxtFile(infile, outfile, privateKey);
}

int main(int argc, char *argv[])
{
	int i;
	int len, len1;
	int inlen, outlen;
	unsigned char encrypted_iv[BUFSIZE];
	unsigned char decrypted_iv[BUFSIZE];
	unsigned char buf[BUFSIZE];
	RAND_bytes(iv, 8);
	
	// cipher
	writeToFile("iv.txt", iv, 8);
	encrypt("iv.txt", "encrypted_iv.txt", "public_key");
	len = readFromFile("encrypted_iv.txt", encrypted_iv, 0, BUFSIZE);
	FILE *encrypted = fopen("encrypted.txt", "w+");
	fwrite(&len, sizeof(int), 1, encrypted);
	fwrite(encrypted_iv, len, 1, encrypted);

	printf("creating AES_cipher.txt\n");
	AES_do_crypt_from_file("orig.txt", "AES_cipher.txt", iv);
	
	printf("creating RSA_AES_cipher.txt\n");
	encrypt("AES_cipher.txt", "RSA_AES_cipher.txt", "public_key");
	//RSA_do_crypt_from_file("AES_cipher.txt", "RSA_AES_cipher.txt", publicKey);
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

	decrypt("encrypted_iv.txt", "decrypted_iv.txt", "private_key");
	//RSA_do_decrypt_from_file("encrypted_iv.txt", "decrypted_iv.txt", privateKey);
	readFromFile("decrypted_iv.txt", decrypted_iv, 0, len);
	remove("encrypted_iv.txt");
	remove("decrypted_iv.txt");

	decrypt("encrypted_message.txt", "decrypted_RSA_AES_cipher.txt", "private_key");
	remove("encrypted_message.txt");
	printf("creating decrypted_message.txt\n");
	AES_do_decrypt_from_file("decrypted_RSA_AES_cipher.txt", "decrypted_message.txt", decrypted_iv);

	remove("decrypted_RSA_AES_cipher.txt");
//*/
//	system("pause");
	
	return 0;
}
 
