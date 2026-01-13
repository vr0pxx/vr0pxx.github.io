---
title: "HTB Rebound"
date: 2026-01-08 09:35:00 +0000
categories: [WriteUp, Hack The Box, Machine, Windows]
tags: [Windows, Hack The Box, WriteUp, Insane, Bloodhound, Kerberoasting, PasswordSpray, DACL, Shadow Credential, Command Injection]
image: /assets/img/posts//htb/rebound/Rebound-HTB.png
pin: false
---

# Enumeracion
## NMAP
```shell
» nmap -p- --open --min-rate 8000 -Pn -sS -n  10.129.232.31 -oG allPorts
Starting Nmap 7.93 ( https://nmap.org ) at 2026-01-07 00:14 -04
Nmap scan report for 10.129.232.31
Host is up (0.39s latency).
Not shown: 54590 filtered tcp ports (no-response), 10937 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
49665/tcp open  unknown
49666/tcp open  unknown
49694/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 51.87 seconds
```

## SMB
Podemos enumerar el servicio `SMB` con **NetExec** para ver si tenemos acceso anónimo.
```shell
 » smbclient -L 10.129.232.31 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Shared          Disk
        SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available

```

# Intrusion
## Descubrir usuarios
Podemos enumerar usuarios con `lookupsid`.

```shell
» lookupsid.py a@10.129.232.31 10000 -no-pass
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at 10.129.232.31
[*] StringBinding ncacn_np:10.129.232.31[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: rebound\Administrator (SidTypeUser)
501: rebound\Guest (SidTypeUser)
502: rebound\krbtgt (SidTypeUser)
512: rebound\Domain Admins (SidTypeGroup)
513: rebound\Domain Users (SidTypeGroup)
514: rebound\Domain Guests (SidTypeGroup)
515: rebound\Domain Computers (SidTypeGroup)
516: rebound\Domain Controllers (SidTypeGroup)
517: rebound\Cert Publishers (SidTypeAlias)
518: rebound\Schema Admins (SidTypeGroup)
519: rebound\Enterprise Admins (SidTypeGroup)
520: rebound\Group Policy Creator Owners (SidTypeGroup)
521: rebound\Read-only Domain Controllers (SidTypeGroup)
522: rebound\Cloneable Domain Controllers (SidTypeGroup)
525: rebound\Protected Users (SidTypeGroup)
526: rebound\Key Admins (SidTypeGroup)
527: rebound\Enterprise Key Admins (SidTypeGroup)
553: rebound\RAS and IAS Servers (SidTypeAlias)
571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
1000: rebound\DC01$ (SidTypeUser)
1101: rebound\DnsAdmins (SidTypeAlias)
1102: rebound\DnsUpdateProxy (SidTypeGroup)
1951: rebound\ppaul (SidTypeUser)
2952: rebound\llune (SidTypeUser)
3382: rebound\fflock (SidTypeUser)
5277: rebound\jjones (SidTypeUser)
5569: rebound\mmalone (SidTypeUser)
5680: rebound\nnoon (SidTypeUser)
7681: rebound\ldap_monitor (SidTypeUser)
7682: rebound\oorend (SidTypeUser)
7683: rebound\ServiceMgmt (SidTypeGroup)
7684: rebound\winrm_svc (SidTypeUser)
7685: rebound\batch_runner (SidTypeUser)
7686: rebound\tbrady (SidTypeUser)
7687: rebound\delegator$ (SidTypeUser)

```
 
Usando regex podemos filtrar solo por los users
```bash
» cat users.txt | grep -i sidtypeuser | awk '{print $2}' | sed 's/^rebound\\//'  | sponge users.txt
```