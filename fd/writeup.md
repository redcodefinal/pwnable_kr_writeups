# fd Writeup

This challenge involves file desciptors which allow a programmer to read/write to stdin, stdout, and stderr. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```

The program takes in a number, then subtracts `0x1234` from it, then opens reads in 32 bytes into `buf` from the `fd`. We know from the wikipedia article that stdin is 0, if C's read function takes in 0 as a file descriptor, it will ask the user at the terminal for input (us)! We can then type in our `"LETMEWIN"` string.

First, we need to calculate what `0x1234` is in decimal, because `atoi` takes in a decimal number string as input. We can calculate this a couple ways

## Calculation
### Ruby
1. `ruby -e "puts 0x1234"`

### Radare2
1. Get into radare2
2. `? 0x1234`
3. Radare will output every encoding of `0x1234`.

```bash
fd@ubuntu:~$ r2 fd
 -- This is amazing ...
[0x080483e0]> ? 0x1234
4660 0x1234 011064 4.6K 0000:0234 4660 "4\x12" 0001001000110100 4660.0 4660.000000f 4660.000000
```

## Execution
Typing `./fd 4660` into the terminal produces a blinking cursor and does not end the program, that is because it is waiting for terminal input to continue. Type the password `LETMEWIN` and hit enter.
```bash
fd@ubuntu:~$ ruby -e "puts 0x1234"
4660
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know <KEY>!!
fd@ubuntu:~$ 
```
