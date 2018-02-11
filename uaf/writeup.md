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
We can see the source code, let's try some testing on the program without using any arguments.

**Use**
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


**Free then use**
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



*WITH ARGUMENT USE CASES*

We can see that....

We need to find some way to overwrite `0x00000000004012d2 Man::introduce()` so when it's called after we free it will call `0x000000000040117a Human::give_shell()`

If we gdb and breakpoint `Man::introduce()` and do option 1, it will break, if we do option 3 and then 1 it will seg fault and not break.

```
(gdb) x/20i $pc-10
   0x400fce <main+266>:	mov    -0x38(%rbp),%eax
   0x400fd1 <main+269>:	mov    (%rax),%rax
   0x400fd4 <main+272>:	add    $0x8,%rax
=> 0x400fd8 <main+276>:	mov    (%rax),%rdx
   0x400fdb <main+279>:	mov    -0x38(%rbp),%rax
   0x400fdf <main+283>:	mov    %rax,%rdi
   0x400fe2 <main+286>:	callq  *%rdx
   0x400fe4 <main+288>:	mov    -0x30(%rbp),%rax
   0x400fe8 <main+292>:	mov    (%rax),%rax
   0x400feb <main+295>:	add    $0x8,%rax
   0x400fef <main+299>:	mov    (%rax),%rdx
   0x400ff2 <main+302>:	mov    -0x30(%rbp),%rax
   0x400ff6 <main+306>:	mov    %rax,%rdi
   0x400ff9 <main+309>:	callq  *%rdx
   0x400ffb <main+311>:	jmpq   0x4010a9 <main+485>
   0x401000 <main+316>:	mov    -0x60(%rbp),%rax
   0x401004 <main+320>:	add    $0x8,%rax
   0x401008 <main+324>:	mov    (%rax),%rax
   0x40100b <main+327>:	mov    %rax,%rdi
   0x40100e <main+330>:	callq  0x400d20 <atoi@plt>
(gdb) x/x 0x401578
0x401578 <vtable for Man+24>:	0x004012d2
(gdb) 
0x40157c <vtable for Man+28>:	0x00000000
(gdb) x/i $pc
=> 0x400fd8 <main+276>:	mov    (%rax),%rdx
(gdb) x/x 0x401578
0x401578 <vtable for Man+24>:	0x004012d2
(gdb) 

```
