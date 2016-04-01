#!/usr/bin/python

from time import time
import subprocess, os

def test():
	t0=time()
	p = subprocess.Popen(("../../src/crypto_hybrid.exe", "e", "../../src/orig.txt", "../../src/encrypted.txt")); 
	p.wait();
	return time()-t0

os.system("echo %s" % ((str(test()))))
