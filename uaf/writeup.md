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

**SOURCE CODE ANALYSIS HERE**

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
Let's set a breakpoint on `Man::introduce()` at `0x00000000004012d2`. This way we can see what happens before, and after we free. We know the program is going to crash on the line `m->introduce();`, we need to find that code. When we disassemble main, we won't see a function call listed for `Man::introduce()` this is because `Human::introduce()` is `virtual` meaning it can be overridden, and the function will be stored inside the classes vtable. This results in the code below out of the compiler.

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
(gdb) si
0x0000000000400fd1 in main ()
1: x/i $pc
=> 0x400fd1 <main+269>:	mov    (%rax),%rax
2: /x $rax = 0x2410c50
3: /x *$rax = 0x3f3e3d3c
4: /x $rdx = 0x7fff781e9ed8
5: /x *$rdx = 0x1
(gdb) si
0x0000000000400fd4 in main ()
1: x/i $pc
=> 0x400fd4 <main+272>:	add    $0x8,%rax
2: /x $rax = 0x434241403f3e3d3c
3: /x *$rax = <error: Cannot access memory at address 0x434241403f3e3d3c>
4: /x $rdx = 0x7fff781e9ed8
5: /x *$rdx = 0x1
(gdb) si
0x0000000000400fd8 in main ()
1: x/i $pc
=> 0x400fd8 <main+276>:	mov    (%rax),%rdx
2: /x $rax = 0x434241403f3e3d44
3: /x *$rax = <error: Cannot access memory at address 0x434241403f3e3d44>
4: /x $rdx = 0x7fff781e9ed8
5: /x *$rdx = 0x1
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
At the end, we can see `rax` contains some of our fuzzing data, With a bunch of sequential data. `rax` will be moved into `rdx` which will be the location that is jumped to in the `call *rdx`


We need to find some way to overwrite `0x00000000004012d2 Man::introduce()` so when it's called after we free it will call `0x000000000040117a Human::give_shell()`

#### Testing

**run without arguments**

**run with arguments**

**gathering exploit information**



