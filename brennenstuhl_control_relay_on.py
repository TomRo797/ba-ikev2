import requests
from requests.auth import HTTPDigestAuth
import time

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



if get_relay_state() == True:
    switch_state()
    time.sleep(5)
    switch_state()
else: switch_state()

