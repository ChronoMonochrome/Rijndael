#include <openssl/evp.h>
 
#define BUFSIZE 1024

int do_crypt(char *infile, char *outfile)
{
	int outlen, inlen;
	FILE *in, *out;
	unsigned char key[32]; /* 256- битный ключ */
	unsigned char iv[8]; /* вектор инициализации */
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

int do_decrypt(char *infile, char *outfile)
{
	int outlen, inlen;
	FILE *in, *out;
	unsigned char key[32]; /* 256- битный ключ */
	unsigned char iv[8]; /* вектор инициализации */
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

int main(int argc, char *argv[])
{
	do_crypt("orig.txt", "encrypted.txt");
	do_decrypt("encrypted.txt", "decrypted.txt");
	return 0;
}
 
