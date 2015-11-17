#include <openssl/evp.h>
#include <openssl/rand.h>

int RAND_bytes(unsigned char *buf, int num);

unsigned char key[32] = { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54,
        0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5 }; /* 256- битный ключ */
unsigned char iv[8]; /* вектор инициализации */


#define BUFSIZE 1024 * 4

int AES_do_crypt_source(char *infile, char *outfile)
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
	EVP_EncryptInit(&ctx, cipher, key, iv);
 
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

int AES_do_decrypt_source(char *infile, char *outfile)
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
	EVP_DecryptInit(&ctx, cipher, key, iv);
 
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

int do_crypt_IV_RSA

int main(int argc, char *argv[])
{
	RAND_bytes(iv, 8);

	//AES_do_crypt_source("orig.txt", "encrypted.txt");
	//AES_do_decrypt_source("encrypted.txt", "decrypted.txt");
	return 0;
}
 
