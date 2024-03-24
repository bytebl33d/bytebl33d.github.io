---
layout: single
title:  "CSCBE24 Bad Ransomware Forensics Challenge Writeup"
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

We are given a Zip file encrypted by the "Bad Ransomware!" gang and looking through the file we see that it is not completely encrypted. Based on the `ZIPDIRRECORD` we can make out that inside the zip file there are several TXT files. This means that only the `ZIPFILE` records may be encrypted. Additionally, we know that the gang uses a weak cryptographic design for their ransomware, so it shouldn't be hard to break once we understand how it works.

At the end of the file, we see the following comment:

```
RANSOMWARE_METADATA#WBhPcQWtzGyyqIKbcTDajg==#2D2D2D2D2D424547494E20525341205055424C4943204B45592D
...
078B92A4793#0:256#832:256#1664:256#2496:256#3328:256#4160:256#4992:256#5824:256#6656:256#7488:256
```

At the end of the file we find something that looks like markers. It appears that the malware tries to split the file into 10 blocks and encrypts it. Only part of the Zip file was encrypted so we can assume that the 10 encrypted blocks start every 832 bytes and probably only encrypt the first 256 bytes.

Now based on this information be can try to derive the original XOR key that was used to encrypt the files. We just need to find some plaintext bytes from the original file and then do a Known-Plaintext-Attack (KPA) on the XOR.

### Identifying plaintext

A Zip file usually contains local file headers with information about the file such as the comment, file size and file name, followed by optional "extra" data fields, and then the possibly compressed, possibly encrypted file data. The `ZIPDIRRECORD` also contains some of this information like the file name.

We also need enough plaintext, longer than the key, to decrypt the file. The local file header has the following structure:

```bash
[Signature][version]...[file name length][extra field length][file name]
```

We know that inside the zip file we have several TXT files with names like `report-1.txt`, `report-2.txt` and so on until `report-10.txt`. This information is useful to reconstruct the header. If we take for example the first filename, then we can create a plaintext with the following bytes.

```bash
$ touch plaintext
$ hexedit plaintext
0C 00 00 00  72 65 70 6F  72 74 2D 31  2E 74 78 74
```

This header means that the file name length is 13 (`0C 00` in hex), has no extra data field (hence `00 00` in hex) and has the filename `report-1.txt`.

We can now try to do a KPA attack on the encrypted blocks and this plaintext using [this tool]([DidierStevensSuite/xor-kpa.py at master · DidierStevens/DidierStevensSuite · GitHub](https://github.com/DidierStevens/DidierStevensSuite/blob/master/xor-kpa.py)) from Didier Stevens.

```bash
$ head -c 256 cookies.zip.Encrypted > block0
$ python3 xor-kpa.py plaintext block0
No key found
```

It tells us that no key is found, so we have to increase our plaintext. Looking back at how the local file headers usually look like, the filename commonly follows with an extra field with ID `0x5455` that is a UTC Unix timestamp. We could also try adding this to our plaintext to increase its size a bit.

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

We can again create a new file for the key that can be used for decryption.

```bash
$ touch key
$ hexedit key
29 6B D6 EB  2C A9 03 21  BB EF 5F 5F  4C FC 10 EC
```

### Decrypting the file

We can now decrypt the file by applying the XOR with the key we found on the first 256 bytes for every block.

```bash
split -b 832 cookies.zip.Encrypted -d
```

This will generate 14 files but we can remove the last 3 and everything after the METADATA of the 11th file. We should now have 10 encrypted blocks numbered from `0x00` to `0x09` where the first 256 bytes are encrypted. We select only those and run our KPA again on these files with the key.

```bash
python3 xor-kpa.py -x x00 key | head -c 256 > 0 && tail -c 576 x00 >> 0
```

Repeating this for all the files and reassembling them gives us the original zip file. When we open it we can find the flag inside `report-1.txt`. 

```bash
$ head -c 50 report-1.txt
Est lectus CSC{HD6E8HDKZNDKE090AJ} nunc curabitur 
```