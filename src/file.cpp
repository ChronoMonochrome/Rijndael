#include <stdio.h>
#include <cstdlib>
#include "file.h"
#include "misc.h"

int file::readFromFile(char *infile, char *inbuf, int start, int inbuf_len)
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

int file::readFromFile(char *infile, unsigned char *inbuf, int start, int inbuf_len)
{
        FILE *in = fopen(infile, "rb");
	if (start > 0) {
		char tmp[start];
		fread(tmp, 1, start, in);
	}

	int inlen = fread(inbuf, 1, inbuf_len, in);
	fclose(in);

	return inlen;
}

int file::writeToFile(char *outfile, char *outbuf, int outbuf_len)
{
        FILE *out = fopen(outfile, "w");
	int outlen = fwrite(outbuf, 1, outbuf_len, out);
	fclose(out);

	return outlen;
}

int file::writeToFile(char *outfile, unsigned char *outbuf, int outbuf_len)
{
        FILE *out = fopen(outfile, "w");
	int outlen = fwrite(outbuf, 1, outbuf_len, out);
	fclose(out);

	return outlen;
}

int file::writeToFP(char *infile, FILE *foutfile)
{
	int inlen;
	unsigned char *buf = (unsigned char *)malloc(BUFSIZE);

	FILE *finfile = fopen(infile, "rb");
	for(;;) {
                inlen = fread(buf, 1, BUFSIZE, finfile);
                if(inlen <= 0) break;
                fwrite(buf, 1, inlen, foutfile);
        }

	free(buf);
	fclose(finfile);

}
