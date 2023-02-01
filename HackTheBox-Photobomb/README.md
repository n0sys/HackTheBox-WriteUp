# HackTheBox Photobomb Writeup
<!-- Description -->
![photobomb](imgs/machine.png)
Completed on ??/??/20??
<!-- /Description -->
## Table of Contents
<!-- TOC -->
- [HackTheBox - Photobomb - WriteUp](#hackthebox-photobomb-writeup)
  - [Table of Contents](#table-of-contents)
  - [Let's Get Going!](#lets-get-going)
    - [Enumeration](#enumeration)
      - [Nmap Scan](#nmap-scan)
    - [Exploitation](#exploitation)
    - [Post Exploitation](#post-exploitation)
<!-- /TOC -->
---
## Let's Get Going
### Enumeration
#### Nmap Scan
We start as usual with the nmap scan 
```bash
$ nmap -sC -sV -oN nmap/initial $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-31 13:48 EST
Nmap scan report for 10.10.11.182
Host is up (0.094s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Lets explore further http on port 80

#### Exploring the website
After editing /etc/hosts and visiting the website, we get the following
![photobomb](imgs/website.png)
Clicking the hyperlink directs us to a login form which we will surely try to manipulate! The page source returned nothing interesting. We continued by checking what the server returns in case of bad request
```
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
```
And the 404 response
![photobomb](imgs/404.png)
Looking at the source page, we find a local URL with a port number
```html
 <img src='http://127.0.0.1:4567/__sinatra__/404.png'>
```
We attempted several scans on the port to see if it is active but got no positive results back
#### Nikto scan
We run the nikto scan to get a primary view of possible problems with our website
```bash
$ nikto -h http://$IP
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.182
+ Target Hostname:    10.10.11.182
+ Target Port:        80
+ Start Time:         2023-01-31 13:48:51 (GMT-5)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Root page / redirects to: http://photobomb.htb/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ 1 host(s) tested
+ End Time:           2023-01-31 14:08:06 (GMT-5) (1155 seconds)
---------------------------------------------------------------------------
```
#### Directory Fuzzing
After running the fuzzing for a while, we notice that all results found contain printer and some other characters and they all require authentication to access them. After trying different combinations and getting same response 401 ("/printera", "/printerb"..), we can realise that the developpers must have wanted to block the "/printer/" directory so they return 401 for all "/printer*" URI requests. 
```bash
$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://photobomb.htb/FUZZ -e ".php,.html" -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://photobomb.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________
printer                 [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 159ms]
printer.php             [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 156ms]
printer.html            [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 150ms]
printers.php            [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 159ms]
printers                [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 163ms]
printers.html           [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 164ms]
printerfriendly         [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 139ms]
printerfriendly.php     [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 142ms]
printerfriendly.html    [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 144ms]
printer_friendly        [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 149ms]
printer_friendly.php    [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 152ms]
printer_friendly.html   [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 156ms]
printer_icon            [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 139ms]
printer_icon.php        [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 143ms]
printer_icon.html       [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 140ms]
printer-icon            [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 180ms]
printer-icon.php        [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 179ms]
printer-icon.html       [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 172ms]
printer-friendly        [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 144ms]
printer-friendly.php    [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 137ms]
printer-friendly.html   [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 140ms]
printerFriendly         [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 151ms]
printerFriendly.php     [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 151ms]
printerFriendly.html    [Status: 401, Size: 188, Words: 6, Lines: 8, Duration: 148ms]
``` 
---
### Exploitation
#### Login Form
We can try different tactics to break this login form, which is until now the only clue we have.
For starters, we attempt to test it with burpsuite. The auth request goes as follows
```http
GET /printer HTTP/1.1
Host: photobomb.htb
Cache-Control: max-age=0
Authorization: Basic d3E6cXdxdw==
```
A GET request is sent with the header Authorization containing the value of the base64 of "username:password"
```python
with open("/usr/share/wordlists/rockyou.txt","r") as f:
	with open("./payloads.txt","w") as payloads:
		i=0
		while i==0:
			try:
				 p = f.readline()
			except:
				continue
			if p!='':
				try:
					payloads.write('admin:'+f.readline())
				except:
					continue
			else:
				i=1
```

---
### Post Exploitation
---

> Any feedback would be appreciated. Thank you !
