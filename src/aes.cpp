#include <openssl/evp.h>
#include "misc.h"
#include "aes.h"

int aes::AES_do_crypt_from_file(char *infile, char *outfile, unsigned char *iv)
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

int aes::AES_do_decrypt_from_file(char *infile, char *outfile, unsigned char *iv)
{
	int outlen, inlen;
	FILE *in, *out;
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER * cipher;

	in = fopen(infile, "rb");
	out = fopen(outfile, "wb");

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
