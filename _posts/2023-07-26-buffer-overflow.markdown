---
layout: single
title:  "Buffer Overflow"
date:   2023-08-29 09:22:22 +0200
categories: ['Binary Exploitation']
classes: wide
toc: true
---
## What are memory corruptions?
Memory management vulnerabilities are one of the most important and dangerous vulnerabilities around, even after decades of studies and countermeasures. Memory corruption refers to an attacker modifying a program’s memory, in a way that was not intended by the program.

The key idea of exploiting programs with memory management vulnerabilities is to feed the program input that triggers the vulnerability, i.e. an invalid memory access, hence, further behavior is undefined according to the language specification. Through corrupting program memory, attackers can make the program misbehave: they can potentially make the program leak sensitive info, execute their own code, or make the program crash. Most real-world system-level exploits involve some sort of memory corruption.

## What is a buffer overflow?
Buffers are areas of memory that are meant to hold data. For example, when a program accepts user input to later operate on, a chunk of memory would have to be set aside to store that user input.

A buffer overflow is caused when the data inside the buffer takes up more space than the memory allocated for the buffer, thus causing the data to overwrite adjacent memory locations.

Before the buffer overflow happens, the memory allocation looks like this:
```
 AAAAAAAAAAA                  BBBBBBBCCCCCCCXXXXXXXXXXXXXXXXXXXXXXXXXX 
 <---------------------------><-----><-----><------------------------> 
             Buffer             EBP    RET      Other program data
```
But when the user input size exceeds the size of the buffer, user input could overwrite other potentially important program data:
```
 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXXXXXXXXXXXXXXXXXXX 
 <---------------------------><-----><-----><------------------------> 
             Buffer             EBP    RET      Other program data
```

## Call stack smashing
The simplest attack is to overwrite the return address so that it points to attacker-chosen code (shellcode). The concrete attack will override at least up to the return address, where you provide the input that makes this address point to your own data (code).

### Stack buffer overflow vs heap buffer overflows
#### Stack-based buffer overflow
A stack-based buffer overflow allows an attacker to overflow a buffer with data to override other data on the stack (e.g. function pointer). If the attacker can overwrite this, he can control where the program jumps after executing a particular function, and gaining the ability to control the program entirely.

Usually, the end objective in binary exploitation is to get a **shell** (often called "popping a shell") on the remote computer. The shell provides us with an easy way to run anything we want on the target computer.

The below function is vulnerable to a stack-based buffer overflow. An attacker can provide enough characters to the `tmp` buffer to overflow the return address.
```c
int vulnerable_function( char* one, char* two ){
    char tmp[MAX_LEN];
    strcpy( tmp, one );
    strcat( tmp, two );
    return strcmp( tmp, "file://foobar" );
}
```
#### Heap-based buffer overflow
The heap is a place in memory which a program can use to dynamically create objects. Much like a stack-based overflow, a heap overflow is a vulnerability where more data is read in than can fit in the allocated buffer. This could lead to heap metadata corruption, or corruption of other heap objects, which could in turn provide new attack surfaces.

The vulnerable function below takes a pointer to a vulnerable struct (on the heap). It will copy the data of `one` and `two` into the struct. This is a variant of the previous function that works with data on the heap, rather than on the stack.
```c
typedef struct _vulnerable_struct {
    char buff[MAX_LEN];
    int (*cmp)(char*,char*);
} vulnerable;

int vulnerable_function( vulnerable* s, char* one, char* two ) {
    strcpy( s->buff, one );
    strcat( s->buff, two );
    return s->cmp( s->buff, "file://foobar" );
}
```
Overwriting a function pointer is almost the same as overwriting the return address. An attacker can therefore overflow the `cmp` function pointer, to make the code jump to shellcode in the buffer.

## Code reuse attacks
The idea of putting shell code in memory is relatively easy to mitigate by having permission bits on various pages of memory (executable data or not), or enabling Address Space Layout Randomization (ASLR). Indirect code injection or code reuse attacks will control execution of the program by reusing fractions of existing code. The crux of the attack is to find a way to execute (a chain of) code fractions under the control of the attacker.

If an attacker can reset the stack pointer to any location of choice (e.g. a fake stack) than he can do anything he wants. It allows calls to any function in the program with arbitrary parameters.

In summary, by making a fake stack you can choose a sequence of existing functions in the program with parameters that you can choose. This class of attacks is typically referred to as **jump-to-libc** or **return-to-libc**.

Say we have a stack that is not executable, meaning we can’t make use of shell code in a buffer. However, we can make the program call a system function to open the shell instead. We can find out where the system/exit call function is located in a program:
```shell
# inside gdb: lookup our system and exit call address
(gdb) p system
0xb7e27250
(gdb) p exit
0xb7e1a420

# store shell in environment variable (if not already there)
export shell=/bin/sh
# find address of shell and strip out the 'shell=' part
x/300s $esp
0xbfffffde
```
The idea is to send a bunch of data (787 bytes in this example) until we reach the return address we want to overwrite, and make the return address point to the `system()` call and executing our shell. The final payload looks as follows:
```
payload = 'A'*787 + addr of system() + ret addr for system() + addr of "/bin/sh"
```
When the variables are filled in with their memory addresses, the final exploit code looks as follows:
```python
FILL = "\x41"*787
SYS = "\x50\x72\xe2\xb7"
SYSRET = "\x20\xa4\xe1\xb7"
STR_PTR = "\xe4\xff\xff\xbf"

payload = FILL + SYS + SYSRET + STR_PTR
```
## Data-only attacks
Data corruption may allow the attacker to achieve their goals without diverting the target software from its expected path of machine-code execution, either directly or indirectly. Such attacks are referred to as data-only, or non-control-data attacks. Examples of this are string vulnerabilities that utilize format string functions (e.g. `printf()`) to achieve information leaks or arbitrary code execution.

This attack can be used when a program makes use of input arguments that are not properly sanitized. An attacker can manipulate the program to read or write memory when it isn’t supposed to. The `%x` format specifier is used to print data from the stack or other locations in memory. We can also write arbitrary data to arbitrary locations using the `%n` format specifier.

Suppose we can enter `AAAA.%x.%x.%x.%x` into a simple program that responds with the user input data:
```shell
Hello AAAA.80486e0.bffff70f.0.0.!
```
Then we know there is string format vulnerability. To find out where the format specifiers start reading before our input, we can try increasing the `%x` format specifiers until we encounter our initial A's.
```shell
./program $(python -c 'print("AAAAA" + "%x."*11)'
Hello AAAAA.80486e0.bffff6dc. ... .b7fff000.6c654807.41206f6c.41414141.!
```
This can allow us to read (or even overwrite) any data on the stack. Suppose there is an admin function that only executes whenever the `isAdmin` variable is true. We can look for its address in gdb and overwrite it as follows:
```python
# A is the value written to the target address (can even be a number)
TARGET = "A\x9c\x99\x04\x08"
FSTRING = "%x."*10
NUMBER = "%n."

payload = TARGET + FSTRING + NUMBER
```
These vulnerabilities have become rare nowadays, as most modern compilers produce warnings when format functions are called with non-constant strings (which is the root cause of this vulnerability).

# Countermeasures
Several countermeasures to raise the difficulty to exploit these flaws are:
- **Data Execution Prevention**: marks certain areas of the program as not executable
- **Address Space Layout Randomization (or ASLR)**: randomization of the place in memory where the program, shared libraries, the stack, and the heap are.
- **Relocation Read-Only (or RELRO)**: makes some binary sections read-only.
- **Stack Canaries**: a secret value placed on the stack changing every time the program is started.
