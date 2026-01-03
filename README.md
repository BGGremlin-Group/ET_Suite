# ET5.5 - Evil Twin Wi-Fi Attack Suite

![Project Banner](https://github.com/BGGremlin-Group/ET_Suite/blob/main/Img/ET5.5Banner.png)

# Developed by the *Background Gremlin Group*
*Creating Unique Tools for Unique Individuals*

## Overview

ET5.5 is a comprehensive Python-based tool suite for simulating and demonstrating Wi-Fi attacks, designed for red team and blue team training in controlled lab environments. It includes features like Evil Twin AP creation, deauthentication attacks, beacon spamming, PMKID/SAE capture and cracking, Karma attacks, WPS attacks (Pixie Dust and Reaver brute force), and WPA3 Dragonblood attack. The tool is built with a Text User Interface (TUI) using curses for easy navigation and operation.

**Important Disclaimer**: ~~This tool is for educational and ethical testing purposes only. Use it only on networks and devices you own or have explicit permission to test. Unauthorized use may violate laws like the Computer Fraud and Abuse Act (CFAA) in the US or equivalent laws elsewhere. The developers assume no responsibility for misuse.~~ We're not your nanny. whst you donis on you. we neither endorse the use or misuse of our products. all code is presented as is.

### Evolution of Versions
- **Initial Version**: Basic Evil Twin setup with TUI, deauth, beacon spam, logging, and data saving (txt, json, yaml, pdf).
- **v2**: Added PMKID capture and Karma attack, input validation.
- **v3**: Integrated hashcat for PMKID cracking, bettercap for advanced attacks, improved error handling.
- **v4**: Added bettercap PMKID capture, enhanced TUI with status indicators.
- **v5.0**: WPA3 PMKID support, Wifite automation, cross-platform support (Linux, Parrot OS, Kali, Termux, limited Windows), optimized TUI navigation.
- **v5.5**: Added WPS Pixie Dust, Reaver WPS brute force, WPA3 Dragonblood attack, more responsive progress bars and TUI.

The final version (ET5.5) incorporates all previous features with refinements for robustness and user-friendliness.

## Features
- **TUI Interface**: Curses-based menu for easy selection of attacks, with real-time status (monitor mode, AP running, captured data counts).
- **Evil Twin AP**: Create fake AP with captive portal for credential capture.
- **Deauthentication Attack**: Disconnect clients using Scapy.
- **Beacon Spam**: Flood with fake AP beacons.
- **PMKID/SAE Capture**: Using hcxdumptool or bettercap, supporting WPA3.
- **Karma Attack**: Rogue AP responding to probe requests.
- **Cracking**: Hashcat integration for PMKID/SAE hashes.
- **Bettercap Integration**: Console and PMKID capture.
- **Wifite Automation**: Run automated Wi-Fi attacks.
- **WPS Attacks**: Pixie Dust (bully) and brute force (reaver).
- **WPA3 Dragonblood**: Invalid curve attack using dragonslayer.
- **Data Saving**: Credentials and hashes saved in txt, json, yaml, PDF.
- **Logging**: Detailed logs in 'evil_twin.log'.
- **Cross-Platform**: Full support for Linux (Kali, Parrot OS), Termux (Android with root); limited for Windows.
- **Progress Bars**: Responsive tqdm bars for attacks.
- **Error Handling**: Robust checks for root, tools, and platforms.

## Requirements
### System Requirements
- **OS**: Linux (Kali, Parrot OS recommended), Android (Termux with root), Windows (limited, requires Npcap for monitor mode).
- **Root/Admin Privileges**: Required for most features (e.g., monitor mode, packet injection).
- **Hardware**: Wi-Fi adapter supporting monitor mode and packet injection (e.g., Alfa AWUS036N, TP-Link WN722N v1).

### Python Dependencies
Install via `pip install -r requirements.txt`.

**requirements.txt**:
```
flask
termcolor
tqdm
fpdf
scapy
pyyaml
curses  # Note: curses is standard in Python, but may need windows-curses on Windows
```

### External Tools
Install these manually as they are not Python packages. Use package managers like apt (Kali/Parrot), pkg (Termux).

- aircrack-ng (airodump-ng, airbase-ng)
- hostapd
- dnsmasq
- iptables
- iwconfig/ifconfig (net-tools)
- hcxdumptool, hcxpcapngtool (for PMKID)
- bettercap
- hashcat
- wifite
- bully (for Pixie Dust)
- reaver (for WPS brute force)
- dragonslayer (for Dragonblood; clone from GitHub: https://github.com/vanhoefm/dragonslayer)

**Installation Commands (Kali/Parrot)**:
```
sudo apt update
sudo apt install aircrack-ng hostapd dnsmasq iptables net-tools hcxtools bettercap hashcat wifite bully reaver
# For dragonslayer: git clone https://github.com/vanhoefm/dragonslayer && cd dragonslayer && make
```

**Termux Setup**:
```
pkg install root-repo
pkg install aircrack-ng hostapd dnsmasq iptables net-tools hcxtools bettercap hashcat wifite bully reaver
# Root Termux device for su access.
```

**Windows**: Limited. Install Npcap for Scapy. Many tools (e.g., hostapd) not available natively; use WSL for full functionality.

## Installation
1. Clone or download the script (e.g., `et55.py`).
2. Install Python dependencies: `pip install -r requirements.txt`.
3. Install external tools as above.
4. Run as root: `sudo python et55.py` (or in Termux: `su -c python et55.py`).

## Usage
- Launch the tool with root privileges.
- Use arrow keys to navigate the TUI menu.
- Press number keys (1-19) to select options directly (supports multi-digit, e.g., 10-19).
- Enter to execute the selected attack.
- Follow on-screen prompts for inputs (SSID, BSSID, channel, etc.).
- Attacks require monitor mode enabled (option 1).
- Captured data is saved automatically or via option 17.
- View logs with option 18.
- Exit with option 19 (cleans up interfaces).

### Example Workflow
1. Enable Monitor Mode (1).
2. Scan APs (3) to find targets.
3. Start Evil Twin (4) with target SSID/channel.
4. Deauth clients (6) to force reconnection.
5. Capture creds via captive portal.
6. Run PMKID attack (8) or crack (11).
7. Save data (17).

## Configuration
- Change `iface = 'wlan0'` to your Wi-Fi interface (use `iwconfig` to find).
- Customize captive portal HTML in `run_portal()`.
- For custom wordlists in cracking, input path when prompted.

## Troubleshooting
- **No monitor mode**: Check adapter compatibility, drivers.
- **Tool not found**: Install missing tools.
- **Permission errors**: Run as root/su.
- **Termux issues**: Ensure rooted device, install root-repo.
- **Windows limitations**: Use Linux VM/WSL for full features.
- Logs in `evil_twin.log` for errors.

  
## License
MIT License.
