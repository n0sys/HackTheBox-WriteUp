# MetaTwo Writeup
<!-- Description -->
![metatwo](imgs/machine2.png)

At the time of writing, MetaTwo is a free access machine on HackTheBox with a difficulity level of Easy. 
We start the machine, get an IP address and start our attack (ofcourse after connecting to HackTheBox network with openvpn).

Completed on ??/??/2023
<!-- /Description -->
## Table of Contents
<!-- TOC -->
- [MetaTwo - WriteUp](#metatwo-writeup)
  - [Table of Contents](#table-of-contents)
  - [Let's Get Going!](#lets-get-going)
    - [Nmap Scan](#nmap-scan)
  - [Conclusion](#conclusion)
<!-- /TOC -->
### Nmap Scan
I start with the usual
```
$ nmap -sC -sV -oN nmap/initial $IP 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-10 15:26 EST
Nmap scan report for 10.10.11.186
Host is up (0.094s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=2/10%Time=63E6A87A%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10\
SF:.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative
SF:\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
So we got ourselvers ftp and http servers to mess with. 
### FTP
### HTTP
#### Nikto Scan
#### Exploring the website


## Conclusion
---
