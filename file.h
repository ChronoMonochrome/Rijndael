using namespace std;


class file
{
public:
int static readFromFile(char *infile, char *inbuf, int start, int inbuf_len);
int static readFromFile(char *infile, unsigned char *inbuf, int start, int inbuf_len);
int static writeToFile(char *outfile, char *outbuf, int outbuf_len);
int static writeToFile(char *outfile, unsigned char *outbuf, int outbuf_len);
int static writeToFP(char *infile, FILE *foutfile);
};
