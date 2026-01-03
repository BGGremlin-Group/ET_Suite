# Evil-Twin Toolkit for Termux

**Developed by the Background Gremlin Group**
“Creating Unique Tools for Unique Individuals”

---

## What it is
A lightweight, menu-driven suite that automates the classic “evil-twin” Wi-Fi assessment workflow inside Termux (or any Debian-based environment).

Use it to:

- Enumerate nearby access points  
- Spin up a configurable rogue AP (evil-twin)  
- Capture voluntary logins via a built-in captive portal  
- Export results in TXT / JSON / YAML / PDF  
- Bonus utilities: de-authentication bursts & beacon-spam

---

⚠️ Legal & Ethical Note
~~This code is released for controlled lab use only (your own hardware, your own networks, or explicit written permission).~~
~~Misuse violates computer-fraud laws in most jurisdictions;~~ the authors accept zero responsibility for unlawful deployments.
We are not your nanny. We neither endorse the use nor misuse of our products. All code is presented as is.

---

## Prerequisites
1. Rooted Android (or a Linux box) – monitor-mode operations require `CAP_NET_RAW`.  
2. Termux (F-Droid build recommended).  
3. Internal Wi-Fi chipset that supports active monitor / AP mode (many modern phones do not; USB-OTG adapters with rtl8812au or mt76xx work best).  
4. 2 GB free space for toolchain + deps.

---

## One-shot Install Script
Copy-paste into a fresh Termux session (internet required):

```bash
pkg update -y && pkg install -y root-repo x11-repo
pkg install -y python git iw configurer iptables aircrack-ng dnsmasq hostapd
pip install --upgrade pip
pip install curses tqdm fpdf2 scapy flask pyyaml termcolor
git clone https://github.com/BGGremlin-Group/ET_Suite/main/Termux.git
cd evil-twin-termux
chmod +x evil_twin.py
```

---

## Quick Start
1. Enable monitor mode  
   
```bash
   sudo python ET1.0.py   # pick option 1
   ```

2. Scan for target APs – note SSID + channel.  
3. Start the rogue AP – supply the cloned SSID & channel (option 3).  
4. Optional: de-auth clients on the real AP (option 5) to accelerate reconnects.  
5. Victims join your AP, see a “Wi-Fi login” page, and credentials appear instantly in the console and `creds.json`.  
6. Stop everything (option 4) and pull reports (option 6).

---

## Menu Map

Key	Action	
1	Put interface into monitor mode	
2	10-second airodump-ng sweep	
3	Launch evil-twin + captive portal	
4	Gracefully shutdown AP & daemons	
5	Targeted or broadcast de-auth	
6	Beacon-spam (fun, not stealthy)	
7	Export captures to TXT/JSON/YAML/PDF	
8	Tail the live log	
9	Exit & return interface to managed	

---

## File Layout

```
ET1.0.py      – main script (no external deps beyond pip list)
hostapd.conf      – generated at runtime
dnsmasq.conf      – generated at runtime
evil_twin.log     – timestamped events
creds.{txt|json|yaml|pdf} – output bundles
```

---

### Tips for Phone-Based Ops
- Use a cooling fan – hostapd + scapy will thermal-throttle most handsets.  
- 5 GHz networks: change `hw_mode=a` in the source if your adapter supports it.  
- Battery saver off; keep screen on to prevent Android dozing the USB radio.  
- OTG Y-cable lets you power the phone while the Wi-Fi dongle is attached.

---

## Troubleshooting

Symptom	Fix	
“Device or resource busy”	Kill competing wpa_supplicant: `su -c 'pkill wpa_supplicant'`	
Portal unreachable	Confirm iptables rule still exists: `iptables -t nat -L`	
No handshake / de-auth fails	Try external antenna; some internal radios ignore injection	
PDF export fails	`pkg install poppler` (gives fpdf2 the fonts it needs)	

---

## License
MIT-style license – see LICENSE file.
