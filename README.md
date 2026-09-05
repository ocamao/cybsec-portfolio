# Antoni M. Consentino — Portfolio de Ciberseguridad

Soy una persona creativa, analítica, proactiva y adaptable, con gran capacidad de aprendizaje y resolución de problemas. Recientemente he aprobado mi primera certificación en ciberseguridad (eJPT), con ganas de aprender más y en búsqueda de mi primera posición en pentesting o SOC junior.

---

## Certificaciones

- **eJPT** — eLearnSecurity / INE Security, Junior Penetration Tester ([mes año])

---

## 🔴 Ofensivo

Writeups de máquinas de [HackMyVM](https://hackmyvm.eu), cada uno con enumeración, explotación, escalada de privilegios y una sección de detección/mitigación.

| Máquina | Dificultad | Resumen |
|---|---|---|
| [Ginger](ofensivo/ginger_hmv.md) | Difícil | WordPress → SQLi → panel admin → SSTI en Flask → cadena de 4 escaladas hasta root |
| [Zen](ofensivo/zen_hmv.md) | Difícil | Credencial oculta en `robots.txt` → RCE vía ZenPhoto → cadena de sudo → secuestro de PATH |
| [Quick5](ofensivo/quick5_hmv.md) | Media | Ataque del lado cliente (macro `.odt`) → credenciales cifradas de Firefox → root |

---

## 🔵 Defensivo

*En construcción — próximamente: análisis de incidentes (triage) sobre retos de CyberDefenders y una detección construida desde cero con Wazuh.*

---

## Herramientas habituales

Nmap · Burpsuite · Gobuster · John the Ripper / Hashcat · CrackMapExec · Impacket · Wireshark · Hydra · Metasploit
