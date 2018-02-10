# flag Writeup

This challenege involves using some basic binary analysis techniques to find a password hidden in the executable.

There is no C code for this challenge, only a single binary. When attempting to use GDB to debug, it won't allow any sort of debugging.

## Solution

`strings flag` produces 
```
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
```

The executable has been packed with some sort of packer. Is it in the ubuntu repos?
```bash
stonercoding@stonercoding:~/Documents/pwnable_kr_writeups/flag$ apt-cache search upx
clamav - anti-virus utility for Unix - command-line interface
upx-ucl - efficient live-compressor for executables
```
We then `sudo apt-get install upx-ucl`.

Once finished we run `upx --help` and find that the decompress flag is `-d`. We then run `upx -d flag`.

UPX will decompress the executable and now we can run `strings flag`. Look for a line that looks like a key. Good luck :)
