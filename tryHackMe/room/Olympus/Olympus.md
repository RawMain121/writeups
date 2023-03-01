# Olympus
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

![http://olympus.thm/](https://github.com/RawMain121/writeups/blob/sandboxInit/tryHackMe/room/Olympus/data/HTTP_olympus.thm.png?raw=true)

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

