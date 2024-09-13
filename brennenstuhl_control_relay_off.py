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
        
