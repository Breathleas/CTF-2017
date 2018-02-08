#include <fstream>
#include <string>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <cstdio>

#include "./CryptoUtils.h"
#include "stdio.h"

using namespace std;

int main(int argc, char ** argv){

	CryptoUtils crypt;
	string key = "BAADF00DCAFEBABE3043544620170318";
	crypt.prng_seed(key);


	char scrambling_key[16];
	crypt.get_bytes(scrambling_key, 16);

	//for (int i=0;i<16;i++){
	//	printf("%02X", ((unsigned) scrambling_key[i]) &0xFF);
	//}
	//printf("\n");

	unsigned n = 0;
	for (int i = 0; i< 100; i++){
	//while(1){
		n = crypt.scramble32(i, scrambling_key);
		printf("%d\n", n);
	}
	
	return 0;
}

/* root@kali:~/Desktop/D/CTF/0CTF_2017/re_choices# ./a.out | ./choices/Choices
Correct!! The flag is flag{wHy_d1D_you_Gen3R47e_cas3_c0nst_v4lUE_in_7h15_way?}
*/