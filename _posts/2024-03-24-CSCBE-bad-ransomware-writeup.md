---
layout: single
title:  "CSCBE24 - Bad Ransomware Forensics Challenge Writeup"
seo_title: "Writeup for the bad ransomware forensics challenge in the Cyber Security Challenge Belgium 24 Qualifiers"
date:   2024-03-24 17:30:00 +0200
categories: ['Forensics', 'CTF']
classes: wide
toc: true
excerpt: Ransomware attacks are becoming more common every day. This forensics challenge goes in depth into the solution of the 'Bad Ransomware' challenge of the CSCBE24 Qualifiers dealing with a Known Plain-Text Attack on an encrypted zip archive.
---

## Bad Ransomware

## Description

Ransomware encrypted file by "connemara" with a slight variation on the magic sequence.

## Scenario

A cookie factory was attacked by the “Bad Ransomware!” ransomware gang.
All their cookie recipes have been encrypted.
It is your job to recover the cookie recipes!

You have one advantage: you know that the cryptographic design of their ransomware application is flawed.

Good luck!

## Solution

We are given a Zip file encrypted by the "Bad Ransomware!" gang. Looking through the file we can see that it is not completely encrypted. Based on the `ZIPDIRRECORD` we can make out that there are several TXT files present. This could mean that only the `ZIPFILE` records are encrypted. Additionally, we know that the gang uses a weak cryptographic design for their ransomware, so it shouldn't be hard to break once we understand how it works.

At the end of the file, we see the following comment that also contains some markers:

```
RANSOMWARE_METADATA#WBhPcQWtzGyyqIKbcTDajg==#2D2D2D2D2D424547494E20525341205055424C4943204B45592D
...<SNIP>...
078B92A4793#0:256#832:256#1664:256#2496:256#3328:256#4160:256#4992:256#5824:256#6656:256#7488:256
```

It appears that the malware tries to split the file into several blocks and then encrypts them. Since we know that only part of the Zip file was encrypted, we can assume that the 10 blocks start every 832 bytes and are probably only encrypted up until the first 256 bytes.

One weak encryption method is XORing the data with a key. Based on the information we have, we can try to derive the original XOR key that was used to encrypt the files. We just need to find some plaintext bytes from the original file and then do a Known-Plaintext-Attack (KPA) on the XOR.

### Identifying Plaintext

A Zip file usually contains local file headers with information about the file such as the comment, file size, file name, optional "extra" data fields, and then the possibly compressed or encrypted file data. The `ZIPDIRRECORD` also contains some of this information (i.e. the file name).

To perform a KPA we need enough plaintext, longer than the key used to encrypt the file, to decrypt it. The local file header has the following structure:

```bash
[Signature][version]...[file name length][extra field length][file name]...
```

We know that inside the zip file we have several TXT files with names like `report-1.txt`, `report-2.txt` and so on until `report-10.txt`. This information is useful to reconstruct the header. If we take for example the first filename, then we can create a plaintext with the following bytes.

```bash
$ touch plaintext
$ hexedit plaintext
0C 00 00 00  72 65 70 6F  72 74 2D 31  2E 74 78 74
```

This header means that the file name length is 12 (`0C 00` in hex), has no extra data field (hence `00 00` in hex) and has the filename `report-1.txt`.

We can now try to do a KPA attack on the encrypted blocks and the plaintext using [this tool]([DidierStevensSuite/xor-kpa.py at master · DidierStevens/DidierStevensSuite · GitHub](https://github.com/DidierStevens/DidierStevensSuite/blob/master/xor-kpa.py)) from Didier Stevens.

```bash
$ head -c 256 cookies.zip.Encrypted > block0
$ python3 xor-kpa.py plaintext block0
No key found
```

The tool tells us that no key is found, meaning we have to increase our plaintext size. Looking back at how the local file headers usually look like, the filename commonly follows with an extra field ID `0x5455` which is a UTC Unix timestamp. We could also try adding this to our plaintext to increase its size a bit.

```bash
0C 00 00 00  72 65 70 6F  72 74 2D 31  2E 74 78 74  55 54
```

Running the tool again will give us a potential key.

```bash
python3 xor-kpa.py clear block0 
Key:       b')k\xd6\xeb,\xa9\x03!\xbb\xef__L\xfc\x10\xec'
Key (hex): 0x296bd6eb2ca90321bbef5f5f4cfc10ec
Extra:     2
Divide:    1
Counts:    1
Keystream: b'\xbb\xef__L\xfc\x10\xec)k\xd6\xeb,\xa9\x03!\xbb\xef'
```

We can again create a new file for the key.

```bash
$ touch key
$ hexedit key
29 6B D6 EB  2C A9 03 21  BB EF 5F 5F  4C FC 10 EC
```

### Decryption

We can now decrypt the file by applying the XOR with the key we found on the first 256 bytes for every block. First, we need to split the original encrypted zip file so we can more easily extract the encrypted data.

```bash
split -b 832 cookies.zip.Encrypted -d
```

This will generate 14 files with a size of 832 bytes but we can remove the last 3 files and everything after the METADATA of the 11th file, since this doesn't contain any encrypted data. We should now have 10 encrypted blocks numbered from `0x00` to `0x09` where the first 256 bytes are encrypted. We perform the KPA only on the encrypted bits with the key. Next we will append the unencrypted part of the file to the end of it.

```bash
python3 xor-kpa.py -x x00 key | head -c 256 > 0 && tail -c 576 x00 >> 0
```

Repeating this for all the files and reassembling them gives us the original zip file. When we open it we can find the flag inside `report-1.txt`. 

```bash
$ head -c 50 report-1.txt
Est lectus CSC{HD6E8HDKZNDKE090AJ} nunc curabitur 
```