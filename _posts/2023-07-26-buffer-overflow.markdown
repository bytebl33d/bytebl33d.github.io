---
layout: single
title:  "Buffer Overflow"
date:   2023-07-26 17:22:22 +0200
categories: binary exploitation
classes: wide
---
## What are memory corruptions?
Memory management vulnerabilities are one of the most imporant and dangerous vulnerabilities around, even after decades of studies and countermeasures. Memory corruption refers to an attacker modifying a program’s memory to her will, in a way that was not intended by the program.

The key idea of exploiting programs with memory management vulnerabilities is to feed the program input that triggers the vulnerability, i.e. an invalid memory access, hence, further behavior is
undefined according to the language specification. Through corrupting program memory, an attacker can make the program misbehave: she can potentially make the program leak sensitive info, execute her own code, or make the program crash. Most real-world system-level exploits involve some sort of memory corruption.

## What is a buffer overflow?
Buffers are areas of memory that are meant to hold data. For example, when a program accepts user input to later operate on, a chunk of memory would have to be set aside to store that user input.

Buffer overflow refers to when a program writes data to a buffer, the data takes up more space than the memory allocated for the buffer, thus causing the data to overwrite adjacent memory locations.

Before the buffer overflow happens, the memory allocation looks like this:
{% highlight python %}
 AAAAAAAAAA                   BBBBB  RRRRR  XXXXXXXXXXXXXXXXXXXXXXXX
<---------------------------><-----><-----><------------------------>
           Buffer               EBP    RET      Other program data
{% endhighlight %}
But when the user input size exceeds the size of the buffer, user input could overwrite other potentially important program data:
{% highlight python %}
 AAAAAAAAAAAAAAAAAAAAAAAAAAA  AAAAA  AAAAA  AAXXXXXXXXXXXXXXXXXXXXX
<---------------------------><-----><-----><------------------------>
           Buffer               EBP    RET      Other program data
{% endhighlight %}

## Call stack smashing
The simplest attack is to overwrite the return address so that it points to attacker-chosen code (shellcode). The concrete attack will override at least up to the return address, where you provide the
input that makes this address point to your own data (code). The challenges of this are:
- Make sure to override the return address to point back into your own buffer.
- Put data in the buffer that, when interpreted in machine code, does what you want it to do.

### Stack buffer overflow vs heap buffer overflows
Stack overflows corrupt memory on the stack. This means that values of local variables, function arguments, and return addresses are affected.

Whereas heap overflows refer to overflows that corrupt memory located on the heap. Global variables and other program data are affected (e.g. structs).

## Code reuse attacks
The idea of putting shell code in memory is relatively easy to mitigate by having permission bits on various pages of
memory. Modern processors allow to specify which parts of memory are executable or not. Indirect code
injection or code reuse attacks will control execution of the program by reusing fractions of the existing
code. The crux of the attack is to find a way to execute (a chain of) code fractions under the control of the
attacker.

If an attacker can reset the stack pointer to any location of choice (e.g. a fake stack) than he can do anything he wants. It allows calls to
any function in the program with arbitrary parameters.

In summary, by making a fake stack you can choose a sequence of existing functions in the program with
parameters that you can choose. This class of attacks is typically referred to as jump-to-libc or return-to-libc.

## Data-only attacks
Data corruption may allow the attacker to achieve their goals without diverting the target software from its
expected path of machine-code execution, either directly or indirectly. Such attacks are referred to as data-
only, or non-control-data attacks. Examples of this are string vulnerabilities that utilize format string functions to achieve information leaks or arbitrary code execution.

These vulnerabilities have become rare nowadays, as most modern compilers produce warnings when format functions are called with non-constant strings (which is the root cause of this vulnerability).
