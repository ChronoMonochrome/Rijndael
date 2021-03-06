#include "cryptkey.h"
#include <fstream>

//key length (decimal digits)
#define KEYLENGTH 80

using namespace std;


class rsa
{
  //encrypt a string
  hugeint static encrypt(string &data, const vector<char>  &a, const hugeint &b);
  //decrypt a string
  string static decrypt(hugeint &data, const vector<char>  &a, const hugeint &b);
  //extended Euclidean algorithm
  void static extEuclid (hugeint  a, hugeint  b, hugeint &y);
public:
  //get public and private keys
  void static genKeys(cryptkey &pbkey, cryptkey &prkey);
  //encrypt a text file
  void static encryptTxtFile(const char *in, const char *out, cryptkey &key);
  //decrypt a text file
  void static decryptTxtFile(const char *in, const char*out, cryptkey &key);
  void static RSA_do_encrypt_from_file(char *infile, char *outfile, char *pubKey);
  void static RSA_do_decrypt_from_file(char *infile, char *outfile, char *privKey);
};
