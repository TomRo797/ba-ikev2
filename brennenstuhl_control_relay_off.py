import requests
from requests.auth import HTTPDigestAuth
import time
import sys
from parse_pcap import *
import os
import glob

def get_relay_state():
    get_relay_state_url = 'http://10.0.71.5/cgi/relaySt?Rel=0'
    req_state = requests.get(get_relay_state_url, auth=HTTPDigestAuth('admin', 'admin'), timeout=10)
    relay_state_str = req_state.content.decode('utf-8')
    relay_state_bool = bool
    if relay_state_str == "on": relay_state_bool = True
    else: relay_state_bool = False

    return relay_state_bool


def switch_state():
    # make request
    switch_relay_url = 'http://10.0.71.5/cgi/toggleRelay?Rel=0' #Rel=1 would toggle the other relay
    get_relay_state_url = 'http://10.0.71.5/cgi/relaySt?Rel=0' 
    # user / password is factory set to admin/admin - you better change this quick.
    req_switch = requests.get(switch_relay_url, auth=HTTPDigestAuth('admin', 'admin'), timeout=10)
    req_state = requests.get(get_relay_state_url, auth=HTTPDigestAuth('admin', 'admin'), timeout=10)

    relay_state_str = req_state.content.decode('utf-8')
    relay_state_bool = bool
    if relay_state_str == "on": relay_state_bool = True
    else: relay_state_bool = False
    print(f"Master relay is now active: {relay_state_bool}")


def find_latest_file(directory):
    # Erstelle einen Suchpfad für Dateien mit dem angegebenen Typ
    search_path = os.path.join(directory, "*.pcap")
    
    # Finde alle Dateien im Verzeichnis mit der gewünschten Dateierweiterung
    files = glob.glob(search_path)
    
    if not files:
        print("Keine Dateien gefunden.")
        return None

    # Finde die neueste Datei basierend auf dem Änderungsdatum
    latest_file = max(files, key=os.path.getmtime)
    
    return latest_file


# Execution
if __name__ == "__main__":
    timestamp = int(time.time())

    if get_relay_state() == True:
        switch_state()

    # Error handling
    if len(sys.argv) != 3: exit("uasge: file.py 'ACHELOS TEST SESSION NAME' 'TEST CASE'")

    # Create path var where pcap & log files are stored
    TEST_SESSION = str(sys.argv[1])
    TEST_CASE = str(sys.argv[2])
    PATH = "C:/Users/Laptop/Desktop/Achelos/IKEIPsecInspector1.7.0/workspace/logs/" + TEST_SESSION
    
    if TEST_CASE == "CT2-01":
        pcap_file_name = "IKEv2_ConnectivityTesting_2-01_TC_e9e0953b-0b3c-4b68-a5ec-1ec2dd3d2fbb_" # UNIX timestamp missing

        latest_file = find_latest_file(PATH)
        if latest_file:
            print(f"Packet capture file: {latest_file}")