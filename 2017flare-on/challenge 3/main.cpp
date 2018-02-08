#include<stdio.h>
__int16 __cdecl check(unsigned __int8 *a1, unsigned int a2)
{
  unsigned int v2; // edx
  unsigned __int16 v3; // cx
  unsigned __int8 *v4; // ebx
  unsigned __int16 v5; // di
  signed int v6; // esi
  unsigned __int16 v8; // [esp+0h] [ebp-4h]

  v2 = a2;
  v3 = 255;
  v8 = 255;
  if ( a2 )
  {
    v4 = a1;
    do
    {
      v5 = v8;
      v6 = v2;
      if ( v2 > 0x14 )
        v6 = 20;
      v2 -= v6;
      do
      {
        v5 += *v4;
        v3 += v5;
        ++v4;
        --v6;
      }
      while ( v6 );
      v8 = (v5 >> 8) + (unsigned __int8)v5;
      v3 = (v3 >> 8) + (unsigned __int8)v3;
    }
    while ( v2 );
  }
  return ((v8 >> 8) + (unsigned __int8)v8) | ((v3 << 8) + (v3 & 0xFF00));
}

int main()
{
	unsigned __int16 result;
	unsigned char data[] = {51, 225, 196, 153, 17, 6, 129, 22, 240, 50, 159, 196, 145, 23, 6, 129, 20, 240, 6, 129, 21, 241, 196, 145, 26, 6, 129, 27, 226, 6, 129, 24, 242, 6, 129, 25, 241, 6, 129, 30, 240, 196, 153, 31, 196, 145, 28, 6, 129, 29, 230, 6, 129, 98, 239, 6, 129, 99, 242, 6, 129, 96, 227, 196, 153, 97, 6, 129, 102, 188, 6, 129, 103, 230, 6, 129, 100, 232, 6, 129, 101, 157, 6, 129, 106, 242, 196, 153, 107, 6, 129, 104, 169, 6, 129, 105, 239, 6, 129, 110, 238, 6, 129, 111, 174, 6, 129, 108, 227, 6, 129, 109, 239, 6, 129, 114, 233, 6, 129, 115, 124};
	unsigned char a[121] = {0};
	int i,j;
	for(i=0;i<256;i++){
		printf("%d ",i);
		for(j=0;j<121;j++){
			a[j] = (data[j]^i) + 34;
		}
		result = (unsigned __int16)check(a,121);
		printf("%x\n",result);
		if(result == 0xFB5E)
			printf("\n%d is right\n",i);
	}
	getchar();
}