#include "lkm.h" 

//m=(2^32-1) 
static unsigned long RandMaxSpecLKM=4294967295L; 
  
LKM::LKM() 
{ 
    next = 1L; 
} 

void LKM::initialize(unsigned long seed) 
{ 
    next = seed; 
} 
void LKM::initialize_by_ctime_function() 
{ 
    next = static_cast<unsigned long>(time(NULL)); 
} 
unsigned long LKM::generate() 
{ 
    next = (253801UL * next + 14519UL) % RandMaxSpecLKM; 
    return next; 
} 
unsigned long LKM::generate_in_interval(unsigned long min, unsigned long max) 
{ 
    return generate() % max + min; 
} 

unsigned char *LKM::RAND_bytes(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
		buf[i] = generate_in_interval(0, 255);
}
