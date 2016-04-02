#ifndef LKM_H 
#define LKM_H 
  
#include <ctime> 
  
class LKM 
{ 
public: 
    LKM(); 
  
    void initialize(unsigned long seed); 
  
    void initialize_by_ctime_function(); 
  
    unsigned long generate(); 
  
    unsigned long generate_in_interval(unsigned long min, unsigned long max); 
 
    unsigned char *RAND_bytes(unsigned char *buf, int len);
private: 
    unsigned long next; 
}; 
  
#endif //LKM_H 

