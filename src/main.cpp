#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <ctime>
#include <string.h>

#include "misc.h"
#include "aes.h"
#include "rsa.h"
#include "file.h"
 

unsigned char iv[32];
unsigned char sh[32];
//unsigned char sh[32] = {0x17, 0x18, 0x5b, 0x85, 0x18, 0x49, 0x19, 0x1f, 0x1a, 0x06, 0x14, 0x19, 0x17, 0x09, 0x18, 0x57, 0x17, 0x13, 0x48, 0x1a, 0x1e, 0x4b, 0x1f, 0x1a, 0x1b, 0x30, 0x71, 0x59, 0x30, 0x18, 0x12, 0x48};

void encode(const char *infile, const char *outfile);
void decode(const char *infile, const char *outfile);

void encrypt(char *infile, char *outfile, char *pubKey)
{
	int i;
	int len;
	int inlen;
	unsigned char *encrypted_iv;
	unsigned char *decrypted_iv;
	encrypted_iv = (unsigned char *)malloc(BUFSIZE);
	decrypted_iv = (unsigned char *)malloc(BUFSIZE);


	srand(time(0));
	printf("Generating the IV\n");
	RAND_bytes(iv, 8);

	SHA256(iv, 8, sh);

	for (i = 0; i < 32; i++) {
		printf("%02x ", sh[i]);
	}
	printf("\n");

	file::writeToFile("tmp_iv.txt", sh, 32);
	encode("tmp_iv.txt", "iv.txt");
	
	printf("Encrypting IV\n");
	rsa::RSA_do_encrypt_from_file("iv.txt", "encrypted_iv.txt", pubKey);
	len = file::readFromFile("encrypted_iv.txt", encrypted_iv, 0, BUFSIZE);
	FILE *encrypted = fopen(outfile, "wb+");
	fwrite(&len, sizeof(int), 1, encrypted);
	fwrite(encrypted_iv, len, 1, encrypted);

	printf("Encrypting the source\n");
	aes::AES_do_crypt_from_file(infile, "tmp_AES_cipher.txt", sh);
	encode("tmp_AES_cipher.txt", "AES_cipher.txt");
	
	rsa::RSA_do_encrypt_from_file("AES_cipher.txt", "RSA_AES_cipher.txt", "public_key");
	//remove("AES_cipher.txt");
	
	file::writeToFP("RSA_AES_cipher.txt", encrypted);
	printf("%s was successfully encrypted and written to %s\n", infile, outfile);
	fclose(encrypted);
 	//remove("RSA_AES_cipher.txt");
 	//remove("iv.txt");
 	//remove("encrypted_iv.txt");

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

	printf("Decrypting the IV\n");
	FILE *encrypted = fopen(infile, "rb");
	fread(&len, sizeof(int), 1, encrypted);

	fread(encrypted_iv, len, 1, encrypted);

	printf("Decrypting the source\n");
	FILE *encrypted_message = fopen("encrypted_message.txt", "wb+");
        for(;;) {
                inlen = fread(buf, 1, BUFSIZE, encrypted);
                if(inlen <= 0) break;
                fwrite(buf, 1, inlen, encrypted_message);
        }
	fclose(encrypted);
	fclose(encrypted_message);

	rsa::RSA_do_decrypt_from_file("encrypted_iv.txt", "tmp_decrypted_iv.txt", privKey);
	decode("tmp_decrypted_iv.txt", "decrypted_iv.txt");

	file::readFromFile("decrypted_iv.txt", decrypted_iv, 0, len);
    	for (i = 0; i < 32; i++) {
        	printf("%02x ", decrypted_iv[i]);
    	}
   	printf("\n");

	//remove("encrypted_iv.txt");
	//remove("decrypted_iv.txt");

	rsa::RSA_do_decrypt_from_file("encrypted_message.txt", "tmp_decrypted_RSA_AES_cipher.txt", privKey);
	//remove("encrypted_message.txt");
	decode("tmp_decrypted_RSA_AES_cipher.txt", "decrypted_RSA_AES_cipher.txt");
	aes::AES_do_decrypt_from_file("decrypted_RSA_AES_cipher.txt", outfile, decrypted_iv);
	printf("%s was successfully decrypted and written to %s\n", infile, outfile);

	//remove("decrypted_RSA_AES_cipher.txt");

	free(buf);
	free(encrypted_iv);
	free(decrypted_iv);
}

int main(int argc, char *argv[])
{
  cout << "AES/RSA hybrid cryptosystem\n"; 
  cout << "Copyright (c) 2015 Shilin Victor\n\n";


  try
  {
    if (argc < 4)
      throw commandErr();


    if (argv[1][0] == 'e')
    {
      if (argc == 4)
      {
        cryptkey publicKey, privateKey;


        ifstream test (argv[2]);
        if (!test.good())
          throw fileErr(argv[2]);
        test.close();


	ifstream test1 ("public_key");
	if (!test1.good()) {
	        cout << "Generating keys...\n";
	        rsa::genKeys(publicKey, privateKey);
	        publicKey.saveToFile("public_key");
	        privateKey.saveToFile("private_key");
	}
	test1.close();

        cout << "Encrypting data...\n";
	encrypt(argv[2], argv[3], "public_key");
      }
      else


        if(argc == 5)
        {
          cryptkey publicKey;


          if (!publicKey.loadFromFile(argv[4]))
            throw fileErr(argv[4]);


          cout << "Encrypting data...\n";
          encrypt(argv[2], argv[3], argv[4]);
        }
        else
          throw commandErr();
    }
    else
      if (argv[1][0] == 'g')
      {
        if (argc == 4)
        {
          cryptkey publicKey, privateKey;
          cout << "Generating keys...\n";


          rsa::genKeys(publicKey, privateKey);


          publicKey.saveToFile(argv[2]);
          privateKey.saveToFile(argv[3]);
        }
        else
          throw commandErr();
      }
      else
        if (argv[1][0] == 'd')
        {
          if (argc == 5)
          {
            cryptkey privateKey;


            if (!privateKey.loadFromFile(argv[4]))
              throw fileErr(argv[4]);


            cout << "Decrypting...\n";
	    decrypt(argv[2], argv[3], argv[4]);
          }
          else
            throw commandErr();
        }
        else
          throw commandErr();


  }
  catch(rsaErr &err)
  {
    cout << "Error (rsa): " << err.what() <<endl;
    return 1;
  }
  catch(mathErr &err)
  {
    cout << "Error (hugeint): " << err.what() <<endl;
    return 1;
  }
  catch(commandErr)
  {
    cout << "Usage:\n";
    cout << " e <in> <out> <public_key_path> - Encrypt data from the file <in> to <out>.\n";
    cout << "    If the key is not specified, it will first try to use a file \"public_key\".\n";
    cout << "    If this file is not found, it will be automatically created and saved\n";
    cout << "    in the current directory.\n\n";
    cout << " g <pb_key_path> <pr_key_path> - Generate keys.\n\n";
    cout << " d <in> <out> <private_key_path> - Encrypt data from the file <in> to <out>.\n"; 
  }
  catch(fileErr &err)
  {
    cout << "Error: unable to open file " << err.filename() << endl;
    return 1;
  }

 // system("pause");

  return 0;
}
 