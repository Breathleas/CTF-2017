## REVERSE

### destroy

程序存在多处花指令，主要是jz/jnz、call+pop两种形式的，去掉就好。调试的时候建议把函数sub_401080（写注册表的）给patch了。

输入的密码主要分为两段XXXX.YYYYYYY，中间以"."号隔开。

第一个check是对"."号前的字符，将其转成整数后，能模5余3、模7余2、模13余4，用mathmatic解一下就好，值为

```
303+405*k
```

第二个check是在函数sub_4013D0中，用YYYYYYY和XXXX逐字节相加并减去48，然后在把高四位、低四位都转成字符形式，然后与`5D4A4759477D4C6836723437316E3B6E717A787E747F`比较。

由于提示flag为XDCTF，所以脚本爆破之：

```python
for k in range(1000000):
    a="5D4A4759477D4C6836723437316E3B6E717A787E747F"
    d1 = str(303+455*k)
    a = a.decode("hex")
    data=""
    for i in range(len(a)):
        temp = ord(a[i])+48-ord(d1[i%len(d1)])
        data += chr(temp)
    if data[0:5]=='XDCTF':
        print data
```

得到：

```
XDCTF{He1l020l7klttys}
XDCTFwC`1l020h2flttysy
```

明显第一个哇



### Stealer

程序主要功能就是释放一个dll，并且用输入的字符串作为key，对dll的text代码段进行RC4解密。

在函数sub_412950会对输入作如下操作，奇数位置、偶数位置分别与0xFE、0xE0异或后模25，再加上65或97：

```C++
char *__cdecl sub_412950(int a1, size_t a2)
{
  int v3; // [esp+D0h] [ebp-38h]
  int v4; // [esp+DCh] [ebp-2Ch]
  int v5; // [esp+E8h] [ebp-20h]
  char *v6; // [esp+F4h] [ebp-14h]
  char *v7; // [esp+100h] [ebp-8h]

  v7 = (char *)j__malloc(a2);
  v6 = (char *)j__malloc(a2);
  j__memset(v7, 0, a2);
  j__memset(v6, 0, a2);
  if ( !sub_411898() )
    ExitProcess(0);
  v5 = 0;
  v4 = 0;
  v3 = 0;
  while ( *(_BYTE *)(v5 + a1) )
  {
    if ( v5 % 2 )
      v6[v3++] = (*(char *)(v5 + a1) ^ 0xFE) % 25 + 65;
    else
      v7[v4++] = (*(char *)(v5 + a1) ^ 0xE0) % 25 + 97;
    ++v5;
  }
  j__strcat(v7, v6);
  return v7;
}
```

然后与字符串`rlmlphghFEYKGFGF`比较，这里有个问题，能过check的输入有很多种（如果只包含可见字符的话，至少3的16次方），由于之后对dll的解密必须要正确的输入才解密成功，所以光过check没用。联系了客服说只有小写字母和数字、并且是有意义的字符串，缩小了范围，写了脚本求所有的可能输入：

```python
import string
a="rlmlphghFEYKGFGF"
data = []
for i in range(0,8):
    data.append(ord(a[i])-97)
    data.append(ord(a[i+8])-65)
print data
zidian = string.lowercase + string.digits
print zidian
test = []
for i in range(16):
    temp = []
    if(i%2==1):
        for j in zidian:
            if(ord(j)^0xFE)%25==data[i]:
                temp.append(j)
    if(i%2==0):
        for j in zidian:
            if(ord(j)^0xE0)%25==data[i]:
                temp.append(j)
    print temp
    test.append(temp)
```

结果：

```python
['n', '9']
['e', '3']
['h', '3']
['d', '2']
['i', '4']
['k', '9']
['h', '3']
['y']
['l', '7']
['b', '0']
['d']
['e', '3']
['c']
['b', '0']
['d']
['e', '3']
```

试了好几次，终于得到：n33d4k3y70d3c0d3

解密之后的dll里有个变型的base64，正常的base64字典为：

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

而dll中用到的base64字典为：

```
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/
```

dll中会把一个字符串用变形的base64编码和`Ahr0CdOVl2vTywLSlJe2mY5JB20V`比较，解之得`http://email.163.com`：

然后在函数sub_10012C10里会将一个字符串与`http://email.163.com`做一次比较，只用了前17字节：

```C++
BOOL __cdecl sub_10012C10(char *a1, char *a2)
{
  return (*a2 ^ *a1) == 1
      && (a2[1] ^ a1[1]) == 3
      && (a2[2] ^ a1[2]) == 64
      && (a2[3] ^ a1[3]) == 30
      && (a2[4] ^ a1[4]) == 13
      && (a2[5] ^ a1[5]) == 86
      && (a2[6] ^ a1[6]) == 31
      && (a2[7] ^ a1[7]) == 16
      && (a2[8] ^ a1[8]) == 31
      && (a2[9] ^ a1[9]) == 17
      && (a2[10] ^ a1[10]) == 93
      && (a2[11] ^ a1[11]) == 89
      && (a2[12] ^ a1[12]) == 27
      && (a2[13] ^ a1[13]) == 70
      && (a2[14] ^ a1[14]) == 6
      && (a2[15] ^ a1[15]) == 65
      && (a2[16] ^ a1[16]) == 74;
}
```

解之得`iw4n7y0urp455w0rd`：

```
b = [1,3,64,30,13,86,31,16,31,17,93,89,27,70,6,65,74]
data = ""
for i in range(17):
    temp = ord(a[i])^b[i]
    data += chr(temp)
print data
```

把它与前面的输入拼接在一起，加上flag{}即可：

```
flag{n33d4k3y70d3c0d3iw4n7y0urp455w0rd}
```



## Android

### 工作验证码

秒出的安卓题，看MainActivity发现加载了xdctf.so库，并调用了里面的encrypt和verify函数。

![write up](/images/apk-1.png)

IDA打开so库逆向这两个函数，由于是静态注册的，所以直接可以在export窗口看到：

![write up](/images/apk-2.png)

encrypt函数是将输入与字符串`My_S3cr3t_P@$$W0rD\x00`相异或，然后作base64加密，verify函数是将结果与字符串`KxU+NEhUEFVBaWB4HUAyVgZ3ZnlLamAHAUUHR20zJlk=`比较，逆向求解flag：

```python
a = "My_S3cr3t_P@$$W0rD\x00"
b = "KxU+NEhUEFVBaWB4HUAyVgZ3ZnlLamAHAUUHR20zJlk="
c = base64.b64decode(b)
flag = ""
for i in range(len(c)):
    temp = ord(c[i])^ord(a[i%0x13])
    flag += chr(temp)

print flag
```

flag{7bf56089deft3f42534b7432cf}

### Muggles

也是秒出的安卓题。MainActivity里可以看到加载了test.so库，调用check函数对输入进行判断，rvgs生成flag：

```java
package com.xdctf.muggles;

import android.util.Base64;

public class Sepr {
    private static String a;

    static {
        Sepr.a = "fail";
        System.loadLibrary("test");
    }

    public Sepr() {
        super();
    }

    public final String a(String arg5) {
        String v0_1;
        Object v3 = null;
        int v0 = 0;
        String v1 = new String(Base64.encode(arg5.getBytes(), 0));
        if(v1.equals(v3)) {
            v0_1 = Sepr.a;
        }
        else if(v1.length() == 0) {
            v0_1 = Sepr.a;
        }
        else {
            if(!arg5.equals(v3) && arg5.length() != 0 && (Sepr.check(new String(Base64.encode(arg5.getBytes(), 
                    0))))) {
                v0 = 1;
            }

            if(v0 != 0) {
                return "flag{" + Sepr.rvgs(v1, v1.length()) + "}";
            }

            v0_1 = Sepr.a;
        }

        return v0_1;
    }

    private static native boolean check(Sepr this, String arg1) {
    }

    private static native String rvgs(Sepr this, String arg1, int arg2) {
    }
}


```

IDA加载so库，看到了JNI_Onload函数，发现是动态加载的：

![write up](/images/apk-3.png)

双击JNI_Onload函数，找到注册函数的地址：

![write up](/images/apk-4.png)

双击跳过去：

![write up](/images/apk-5.png)

找到了check函数和rvgs函数对应的地址，这里之所以两个地址会+1，是表示用thumb模式来解析这两个函数，普通的ARM模式是以四字节去解析指令的，而thumb模式则是用二字节解析指令的，所以这里会导致这两个函数IDA识别不出来，用`alt+g`将值修改成1即可正确解析了：

![write up](/images/apk-6.png)

check函数中是对输入的每一字节作变化，将低四位与0xE异或然后转成字符，高四位与0xD异或然后转成字符，与`4898b9febb9889ba48a9898acb3bdb3e4d`比较，写脚本求解：

```python
a = "4898b9febb9889ba48a9898acb3bdb3e4d"
a = a.decode("hex")
input1 = ""
for i in a:
    high = ord(i)>>4
    low = ord(i)&0xf
    temp = (high^0xE)+(low^0xD)*16
    input1 += chr(temp)
print input1
```

结果为`ZWE1eWFuZDFvbmc=`，base64解码一下得`ea5yand1ong`，输入到apk里，就弹出了flag：

```
flag{4888d90ffbc8e90bc85e2e5b88ebb80f4d}
```

