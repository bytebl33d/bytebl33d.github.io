---
layout: blog
title:  "Attacking JSON Web Tokens"
date:   2023-09-02T13:22
categories: ['Web-Exploitation']
---

![](/assets/images/headers/JWT.png)

Incorrect handling of JSON Web Tokens (JWTs) can leave a website vulnerable to a variety of attacks. To understand these attacks we first have to know what a JWT token is.

## What is a JSON Web Token?
JSON Web Tokens are widely used for authentication, session management, and access control purposes in web applications. It is a compact and self-contained way to securely transmit data ("claims") between server and client as a JSON object. These tokens can be signed using a secret or a public/private key pair. A typical JWT token consists of 3 main parts:
- **Header**: contains algorithm and type
- **Payload**: contains user information
- **Signature**: validates the above portions with a secret key or public/private key pair. Without knowing the server's secret signing key, it should be impossible to generate the correct signature for a given header or payload.

All of these parts are separated by a dot character and base64 encoded, as show in the following example:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYnl0ZWJsMzNkIiwic3ViIjoiYnl0ZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.Ovvl3b1UnC1oNYAfBSIVfcoH2b3PtBJJ1iUbehvcZr4
```

## Attacking JWT Tokens
JWT vulnerabilities typically arise due to flawed JWT handling within an application, meaning that the signature of the token is not properly verified. Even if the signature is correctly verified, the trust relies heavily on the security of the secret key.

### Improper signature verification
If the server does not properly verify the signature, anyone is able to make arbitrary changes to the content of the token. For example, suppose the JWT contains the following claims:
```json
{
    "username": "bytebl33d",
    "isAdmin": false
}
```
If the server identifies the session based on the username, modifying its value might enable an attacker to impersonate other logged-in users. Similarly, if the `isAdmin` value is used for access control, this could provide a simple vector for privilege escalation.

### Accepting tokens with no signature
The JWT header contains an `alg` parameter telling the server which algorithm was used to sign the token. This means that it also tells which algorithm to use when verifying the signature.
```json
{
    "alg": "RS256",
    "typ": "JWT"
}
```
JWTs can be signed using a range of different algorithms, but can also be left unsigned. In this case, the `alg` parameter can be set to `none`, which indicates a so-called "unsecured JWT".

### Algorithm confusion attacks
Algorithm confusion attacks (also known as key confusion attacks) occur when an attacker is able to force the server to verify the signature of a JSON web token using a different algorithm than is intended by the website's developers. This vulnerability typically arises because of a flawed implementation of the token verification. Many libraries make use of a generic method to verify the token that rely on the alg parameter in the JWT header.
```js
token = request.getCookie("session");
verify(token, publicKey);
```
Some of the signing algorithms, such as HS256, use a "symmetric" key which is a single key to both sign and verify the token. Using a flawed verification process like above enables an attacker to sign the token using HS256 and the public key, where the server will use that same public key to verify the signature.
The public key can look something like this:
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY
ktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi
XuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg
jIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH
+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx
V8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr
0wIDAQAB
-----END PUBLIC KEY-----
```
This means we can make our own JWTs with a forged signature created using the public key and the HS256 algorithm to bypass the authentication completely. Since the JWT was already signed using the public key, the signature verification by the application is successful leading to a successful key confusion attack.

!!!info Note
In cases where the public key isn't readily available, you may still be able to test for algorithm confusion by deriving the key from a pair of existing JWTs. This process is relatively simple using tools such as [jwt_forgery.py](https://github.com/silentsignal/rsa_sign2n/tree/release/standalone).
!!!

### JWT header parameter injection
Although only the `alg` parameter is mandatory, in practice the header often contain other parameters:
- `jwk` : JSON Web Key (can sometimes be exposed on standard endpoints such as `/.well-know/jswks.json`)
- `jku` : JSON Web Key Set URL for servers to fetch a set of trusted keys
- `kid` : Key ID that servers can use to identify the correct key in cases where there are multiple keys to choose from

#### JWK parameter injection
Ideally, servers should only use a limited whitelist of public keys to verify JWT signatures. However, misconfigurations often lead use to use any key that's embedded in the jwk parameter. This makes it possible to sign a modified JWT using your own RSA private key, and then embedding the matching public key in the `jwk` header. You can see an example of this in the following JWT header:
```json
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```

#### JKU parameter injection
The `jku` parameter points to an endpoint where JWKs are stored used to verify the signature. This can also be changed by an attacker to point to there own generated set of keys.
```json
{
    "alg": "RS256",
    "typ": "JWT",
    "jku":"https://exploit-server.com/key.json" 
}
```
Example content of the `key.json` file:
```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
            "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw"
        }
    ]
}
```

#### KID parameter injection
The `kid` parameter has no concrete structure and can be vulnerable to directory traversal if misconfigured:
```json
{
    "kid": "../../../../dev/null",
    "typ": "JWT",
    "alg": "HS256",
}
```
Of course you can make the parameter point to any file, but the `/dev/null` file that is present in Linux systems returns an empty string. This will sign the token with an empty string and results in a valid signature.

## JSON Web Token Toolkit
The [jwt_tool.py](https://github.com/ticarpi/jwt_tool) is a very useful toolkit for validating, forging, scanning and tampering with JSON Web Tokens. It can test for a variety of known exploits such as the RS/HS256 public key mismatch vulnerability discussed in this article. Let's look at an example that leverages the key confusion attack on a JWT token when we have access to the public key. The `-X k` flag can be used for the key confusion attack.

```console
$ python3 jwt_tool.py <JWT_TOKEN> -X k -pk public.pem
```

Using this tool we can even inject SQL queries in certain payload fields that we are interested in. We can do this using the `-I` flag, specifying the claim `-pc` and value `-pv` of the payload to tamper. In this example we are changing the current username to be 'admin'.

```console
$ python3 jwt_tool.py <JWT_TOKEN> -I -pc username -pv "admin" -X k -pk key.pem
```

### SQL Injection Payloads
If certain functions on the web application are vulnerable to SQL injection, we can even modify the JWT token to include an injection payload of our choice.
```console
$ python3 jwt_tool.py <JWT_TOKEN> -I -pc username -pv "' AND 1 = 0 UNION ALL SELECT 1,group_concat(sql),3 FROM sqlite_master--" -X k -pk public.pem
```
We can then use the newly generated fake token and set it as our session cookie:
```console
$ curl http://<Host>:<PORT>/ -b 'session=<FAKE-TOKEN>'
```
