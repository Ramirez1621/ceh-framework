# CEH Framework — Automation Toolkit
<<<<<<< HEAD
**v1.1.0 · BlueShift**  
=======
**v1.1.0**  
>>>>>>> 83e17e4d31c1a2daada4697605ccc6b6bbc7608a
*Ethical Hacker — Multi-distro Pentesting Automation*

---

## Requisitos del sistema

| Requisito   | Mínimo |
|-------------|--------|
| OS          | Kali Linux, Parrot, Ubuntu/Debian, Arch/Manjaro |
| Python      | 3.10+ |
| RAM         | 2 GB  |
| Privilegios | `sudo` o root (recomendado) |
| WiFi (opcional) | Adaptador con monitor mode + packet injection |

---

## Instalación

```bash
git clone https://github.com/Ramirez1621/ceh-framework.git
cd ceh-framework
chmod +x install.sh
sudo ./install.sh
```

```bash
sudo python3 main.py
```

---

## Módulos

### Reconocimiento — `modules/recon/`

| Módulo | Herramienta | Función |
|--------|-------------|---------|
| `nmap_scan.py` | nmap | 6 perfiles: Quick, Full, Stealth, VersionDetect, Vuln, UDP |
| `osint.py`     | whois / dig | WHOIS, DNS enum, subdominios, transferencia de zona (AXFR) |

---

### Explotación — `modules/exploit/`

| Módulo | Herramienta | Función |
|--------|-------------|---------|
| `msf_handler.py`  | msfconsole  | RC scripts + listener reverso |
| `searchsploit.py` | searchsploit | Auto-hunt por servicios nmap → tabla ordenada + mapper MSF |

SearchSploit detecta automáticamente módulos MSF para: EternalBlue, vsftpd 2.3.4, ProFTPD, Shellshock, Struts2, Tomcat, Drupal, WordPress y 10 más.

---

### Vulnerabilidades — `modules/vuln/`

| Módulo | Herramienta | Función |
|--------|-------------|---------|
| `sqli.py` | sqlmap / manual | Detección SQLi con payloads manuales + SQLMap automático |

---

### Auditoría WiFi — `modules/wifi/wifi_audit.py`

M�dulo de 6 fases para auditoría WPA/WPA2:

```
[ 1/6 ] Verificación de herramientas  → instala tshark, cowpatty, hcxtools si faltan
[ 2/6 ] Detección de interfaces       → tabla con driver, chipset, modo
[ 3/6 ] Verificación capacidades      → soporte monitor mode via iw phy
[ 4/6 ] Modo monitor                  → airmon-ng + 2 fallbacks
[ 5/6 ] Escaneo de redes              → airodump-ng 2.4+5 GHz, tabla con señal/enc
[ 6/6 ] Ataque                        → wifite (automático) + aircrack-ng (manual)
```

**rockyou.txt:** resuelve symlinks de Kali automáticamente (`zcat → /tmp/ceh_rockyou.txt`).

**Reportes generados en `reports/`:**
```
wifi_audit_<ESSID>_<timestamp>.txt        ← resultado + contraseña
wifi_<ESSID>_<timestamp>_wifite_output.txt
wifi_<ESSID>_<timestamp>_aircrack_output.txt
wifi_<ESSID>_<timestamp>_handshake_<BSSID>.cap
```

**Hardware recomendado:** Alfa AWUS036NHA / AWUS036ACH · TP-Link TL-WN722N **v1** (v2/v3 sin inyección)

---

### Ataque Rápido Full

```
FASE 1  OSINT       → WHOIS + DNS
FASE 2  NMAP        → Quick Scan + -Pn automático
FASE 3  SEARCHSPLOIT → auto-hunt de exploits
FASE 4  MSF         → lanzar exploit (opcional)
```

---

## Herramientas verificadas en el banner de inicio

| Grupo | Herramientas |
|-------|-------------|
| Reconocimiento | nmap, whois, dig, curl |
| Explotación | msfconsole, searchsploit |
| Web / Vuln | nikto, gobuster, sqlmap, hydra |
| WiFi | aircrack-ng, wifite, tshark, cowpatty, hcxpcapngtool, iw |

Estado: `✔ OK` instalada · `✗ N/A` faltante (ejecuta `./install.sh`)

---

## Estructura del proyecto

```
ceh-framework/
├── main.py
├── install.sh
├── requirements.txt
├── core/
│   ├── banner.py       ← Banner + verificación de 16 herramientas
│   ├── compat.py       ← Detección distro, mapeo tool→paquete
│   ├── privileges.py   ← SUDO_PREFIX, require_root()
│   └── utils.py        ← run_command, save_report
├── modules/
│   ├── recon/          ← nmap_scan.py, osint.py
│   ├── exploit/        ← msf_handler.py, searchsploit.py
│   ├── vuln/           ← sqli.py
│   └── wifi/           ← wifi_audit.py
└── reports/
```

---

> ⚠ Herramienta para uso **exclusivamente autorizado**. El autor no se responsabiliza por uso indebido.  
> *CEH Framework · Ferney Ramirez · 2026*
