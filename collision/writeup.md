# col Writeup

This challenge involves exploiting a vulnerable hashing function that could allow an attacker to craft collisions.

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```

This program takes an argument in, and runs a hashing function on it before comparing it to `hashcode` and deciding access. The vulnerable part here is in the `check_password` function. We see it takes the string argment a `char*` and casts it to an `int*`. This takes every 4 chars in the string and reads them as one integer. The function then goes over all 5 integers and adds the together. 

To solve this we need to solve think mathmatically. If the function just takes these integers and adds them together we can infer a couple things.

1. The order of the integers does not matter.
2. The order of the bytes within each integer does matter. 

This means that if we take `hashcode`, divide it by 4 , and put that number into each of the integers that is going into `check_passcode`, we can easily reproduce the password without brute force. Let's do some calculations.

```
col@ubuntu:~$ irb
irb(main):001:0> 0x21DD09EC/5.0
=> 113626824.8
```
Unfortunately, its not a whole number, but this isn't too bad, lets find out how much is left over.

```
irb(main):002:0> 0x21DD09EC%5.0
=> 4.0
```
Ok, so if we were to pack out number `113626824` into `./col` we will be only four off from hitting the hashcode! We can add the 4 back to one of the bytes, or just distribute it out between the four integers. It doesn't matter.
```
irb(main):003:0> 113626824.to_s 16
=> "6c5cec8"
irb(main):003:0> 113626825.to_s 16
=> "6c5cec9"
```
Next we want to take these bytes we got and pack them into an argument. The first 4 bytes will go in front, then the last 4 integers will be the second set of 4 bytes.

## Solution
### Input as argument
`./col $'\xc8\xce\xc5\x06\xc9\xce\xc5\x06\xc9\xce\xc5\x06\xc9\xce\xc5\x06\xc9\xce\xc5\x06'`

```bash
col@ubuntu:~$ ./col $'\xc8\xce\xc5\x06\xc9\xce\xc5\x06\xc9\xce\xc5\x06\xc9\xce\xc5\x06\xc9\xce\xc5\x06'
daddy! I just <KEY>
```

 
 


