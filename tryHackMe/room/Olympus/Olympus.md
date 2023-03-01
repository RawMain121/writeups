# Olympus
target: 10.10.207.20


## Recon

---
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

![http://olympus.thm/](https://github.com/RawMain121/writeups/blob/main/tryHackMe/room/Olympus/data/HTTP_olympus.thm.png)

Before trying to explorate the web page, we can launch gobuster:

