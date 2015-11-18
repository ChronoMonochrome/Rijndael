#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

#include "private/misc.h"
#include "private/aes.h"
#include "private/rsa.h"

 

unsigned char iv[8];
 
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
	unsigned char encrypted_iv[BUFSIZE];
	unsigned char decrypted_iv[BUFSIZE];
	unsigned char buf[BUFSIZE];
	RAND_bytes(iv, 8);
	
	// cipher
	len = RSA_do_crypt_source(iv, publicKey, encrypted_iv);
	FILE *encrypted = fopen("encrypted.txt", "w+");
	fwrite(&len, sizeof(int), 1, encrypted);
	fwrite(encrypted_iv, len, 1, encrypted);

	printf("creating AES_cipher.txt\n");
	AES_do_crypt_from_file("orig.txt", "AES_cipher.txt", iv);
	
	printf("creating RSA_AES_cipher.txt\n");
	RSA_do_crypt_from_file("AES_cipher.txt", "RSA_AES_cipher.txt", publicKey);
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

	RSA_do_decrypt_from_file("encrypted_iv.txt", "decrypted_iv.txt", privateKey);
	readFromFile("decrypted_iv.txt", decrypted_iv, 0, len);
	remove("encrypted_iv.txt");
	remove("decrypted_iv.txt");

	RSA_do_decrypt_from_file("encrypted_message.txt", "decrypted_RSA_AES_cipher.txt", privateKey);
	remove("encrypted_message.txt");
	printf("creating decrypted_message.txt\n");
	AES_do_decrypt_from_file("decrypted_RSA_AES_cipher.txt", "decrypted_message.txt", decrypted_iv);

	remove("decrypted_RSA_AES_cipher.txt");
	
	return 0;
}
 
