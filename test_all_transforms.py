""" Imports """
import pyautogui
import time

""" Defines """
PARAM_PATH = "C:/Users/tomro/Documents/Abschlussarbeit/Motivators/Parameters.xml"

# Definiert nach https://man.openbsd.org/iked.conf#CRYPTO_TRANSFORMS
encryption_algorithms = {
    0: "3des",
    1: "aes-128",
    2: "aes-192",
    3: "aes-256",
    4: "aes-128-ctr",
    5: "aes-192-ctr",
    6: "aes-256-ctr",
    7: "aes-128-gcm",
    8: "aes-192-gcm",
    9: "aes-256-gcm",
    10: "aes-128-gcm-12",
    11: "aes-256-gcm-12",
    12: "blowfish",
    13: "cast",
    14: "chacha20-poly1305",
}

# Definiert nach https://man.openbsd.org/iked.conf#CRYPTO_TRANSFORMS
prf_algorithms = {
    0: "hmac-md5",
    1: "hmac-sha1",
    2: "hmac-sha2-256",
    3: "hmac-sha2-384",
    4: "hmac-sha2-512",
}

# Definiert nach https://man.openbsd.org/iked.conf#CRYPTO_TRANSFORMS
integrity_algorithms = {
    0: "hmac-md5",
    1: "hmac-sha1",
    2: "hmac-sha2-256",
    3: "hmac-sha2-384",
    4: "hmac-sha2-512",
}

authentication_algorithms = {
    0: "psk",
    1: "rfc7427",
    2: "pubkey",
    3: "eap",
    4: "null",
}

# Definiert nach https://man.openbsd.org/iked.conf#CRYPTO_TRANSFORMS
dh_groups = {
    0: "modp768",
    1: "modp1024",
    2: "modp1536",
    3: "modp2048",
    4: "modp3072",
    5: "modp4096",
    6: "modp6144",
    7: "modp8192",
    8: "ecp256",
    9: "ecp384",
    10: "ecp521",
    11: "ecp192",
    12: "ecp224",
    13: "brainpool224",
    14: "brainpool256",
    15: "brainpool384",
    16: "brainpool512",
    17: "curve25519",
    18: "sntrup761x25519",
}

""" Methods """
def start_ct201(testcase: str, LAST_KNOWN_GOOD: str) -> bool:
    IMG_PATH = "C:/Users/Laptop/Desktop/test_all_transforms/images/"
    STATUS = 0

    time.sleep(1)

    try: pos1 = pyautogui.locateOnScreen(IMG_PATH + "ct2-01_failed.PNG", confidence=0.95)
    except pyautogui.ImageNotFoundException:
        try: pos1 = pyautogui.locateOnScreen(IMG_PATH + "ct2-01_success.PNG", confidence=0.95)
        except pyautogui.ImageNotFoundException:
            with open(PARAM_PATH, "w") as new_config_xml:
                new_config_xml.write(LAST_KNOWN_GOOD)
            exit("Could not find 'ConnectivityTesting#2-01' testcase. Exiting.")

    pyautogui.moveTo(pos1[0]+15, pos1[1]+15, duration=0.5)
    time.sleep(0.5)
    pyautogui.rightClick()
    time.sleep(0.5)
    pyautogui.moveTo(pos1[0]+80, pos1[1]+50, duration=0.5)
    time.sleep(0.5)
    pyautogui.click()
    time.sleep(1)

    while True:
        try: 
            pos2 = pyautogui.locateOnScreen(IMG_PATH + "ct2-01_waiting.PNG", confidence=0.98)
            time.sleep(3)
        except pyautogui.ImageNotFoundException:
            try: 
                pos2 = pyautogui.locateOnScreen(IMG_PATH + "ct2-01_success.PNG", confidence=0.98)
                print(f"Testcase '{testcase}' status: SUCCESS")
                STATUS = True
                break
            except pyautogui.ImageNotFoundException:
                try: 
                    pos2 = pyautogui.locateOnScreen(IMG_PATH + "ct2-01_failed.PNG", confidence=0.98)
                    print(f"Testcase '{testcase}' status: FAILED")
                    STATUS = False
                    break
                except pyautogui.ImageNotFoundException:
                    with open(PARAM_PATH, "w") as new_config_xml:
                        new_config_xml.write(LAST_KNOWN_GOOD)
                    exit("Could not find 'ConnectivityTesting#2-01' testcase. Exiting.")
    
    return STATUS
                    
def test_all_auth_single(LAST_KNOWN_GOOD: str) -> list:
    print("Testing all single round authentication algorithms...")

    list_of_auths = []
    with open(PARAM_PATH, "r") as config_xml:
            current_xml = config_xml.read()
    if not LAST_KNOWN_GOOD: LAST_KNOWN_GOOD = current_xml

    for i in range(len(authentication_algorithms)):
        current_xml = LAST_KNOWN_GOOD
        pos = current_xml.find('<parameter id="AUTH_MODE_ROUND_1">') + 55
        current_xml_start = current_xml[:pos]
        current_xml_end = current_xml[pos:]
        pos2 = current_xml_end.find("</string>")
        current_xml_end = current_xml_end[pos2:]
        current_xml = current_xml_start + authentication_algorithms[i] + current_xml_end

        pos3 = current_xml.find('<parameter id="AUTH_MODE_ROUND_2">') + 55
        current_xml_start = current_xml[:pos3]
        current_xml_end = current_xml[pos3:]
        pos4 = current_xml_end.find("</string>")
        current_xml_end = current_xml_end[pos4:]
        current_xml = current_xml_start + current_xml_end
        
        with open(PARAM_PATH, "w") as new_config_xml:
            new_config_xml.write(current_xml)

        time.sleep(1)

        start_timestamp = time.time()
        result = start_ct201(f"AUTH Single: {authentication_algorithms[i]}", LAST_KNOWN_GOOD)
        end_timestamp = time.time()
        duration = round(end_timestamp - start_timestamp, 2)
        list_of_auths.append([authentication_algorithms[i], result, duration])
    
    with open(PARAM_PATH, "w") as new_config_xml:
        new_config_xml.write(LAST_KNOWN_GOOD)

    print("Finished testing all single round authentication algorithms.\n")
    return list_of_auths

def test_all_auth(LAST_KNOWN_GOOD: str) -> list:
    print("Testing all rounds authentication algorithms...")

    list_of_auths = []
    with open(PARAM_PATH, "r") as config_xml:
            current_xml = config_xml.read()
    if not LAST_KNOWN_GOOD: LAST_KNOWN_GOOD = current_xml

    for i in range(len(authentication_algorithms)):
        current_xml = LAST_KNOWN_GOOD
        pos = current_xml.find('<parameter id="AUTH_MODE_ROUND_1">') + 55
        current_xml_start = current_xml[:pos]
        current_xml_end = current_xml[pos:]
        pos2 = current_xml_end.find("</string>")
        current_xml_end = current_xml_end[pos2:]
        current_xml = current_xml_start + authentication_algorithms[i] + current_xml_end
        for j in range(len(authentication_algorithms)):
            pos3 = current_xml.find('<parameter id="AUTH_MODE_ROUND_2">') + 55
            current_xml_start = current_xml[:pos3]
            current_xml_end = current_xml[pos3:]
            pos4 = current_xml_end.find("</string>")
            current_xml_end = current_xml_end[pos4:]
            current_xml = current_xml_start + authentication_algorithms[j] + current_xml_end
        
            with open(PARAM_PATH, "w") as new_config_xml:
                new_config_xml.write(current_xml)

            time.sleep(1)

            start_timestamp = time.time()
            result = start_ct201(f"AUTH Double: Auth1: {authentication_algorithms[i]} Auth2: {authentication_algorithms[j]}", LAST_KNOWN_GOOD)
            end_timestamp = time.time()
            duration = round(end_timestamp - start_timestamp, 2)
            combination = f"Auth1: {authentication_algorithms[i]} Auth2: {authentication_algorithms[j]}"
            list_of_auths.append([combination, result, duration])
    
    with open(PARAM_PATH, "w") as new_config_xml:
        new_config_xml.write(LAST_KNOWN_GOOD)

    print("Finished testing all rounds authentication algorithms.\n")
    return list_of_auths

def test_all_dh_groups(LAST_KNOWN_GOOD: str) -> list:
    print("Testing all Diffie-Hellman-Groups...")

    list_of_groups = []
    with open(PARAM_PATH, "r") as config_xml:
            current_xml = config_xml.read()
    if not LAST_KNOWN_GOOD: LAST_KNOWN_GOOD = current_xml

    for i in range(len(dh_groups)):
        current_xml = LAST_KNOWN_GOOD
        pos = current_xml.find('<parameter id="CIPHER_IKE_SA_GROUP">') + 57
        current_xml_start = current_xml[:pos]
        current_xml_end = current_xml[pos:]
        pos2 = current_xml_end.find("</string>")
        current_xml_end = current_xml_end[pos2:]
        current_xml = current_xml_start + dh_groups[i] + current_xml_end
        
        with open(PARAM_PATH, "w") as new_config_xml:
            new_config_xml.write(current_xml)

        time.sleep(1)

        start_timestamp = time.time()
        result = start_ct201(f"DH: {dh_groups[i]}", LAST_KNOWN_GOOD)
        end_timestamp = time.time()
        duration = round(end_timestamp - start_timestamp, 2)
        list_of_groups.append([dh_groups[i], result, duration])
    
    with open(PARAM_PATH, "w") as new_config_xml:
        new_config_xml.write(LAST_KNOWN_GOOD)

    print("Finished testing all Diffie-Hellman-Groups.\n")
    return list_of_groups
            

def test_all_prf(LAST_KNOWN_GOOD: str):
    print("Testing all pseudo random functions...")

    list_of_prfs = []
    with open(PARAM_PATH, "r") as config_xml:
            current_xml = config_xml.read()
    if not LAST_KNOWN_GOOD: LAST_KNOWN_GOOD = current_xml

    for i in range(len(prf_algorithms)):
        current_xml = LAST_KNOWN_GOOD
        pos = current_xml.find('<parameter id="CIPHER_IKE_SA_PRF">') + 55
        current_xml_start = current_xml[:pos]
        current_xml_end = current_xml[pos:]
        pos2 = current_xml_end.find("</string>")
        current_xml_end = current_xml_end[pos2:]
        current_xml = current_xml_start + prf_algorithms[i] + current_xml_end
        
        with open(PARAM_PATH, "w") as new_config_xml:
            new_config_xml.write(current_xml)

        time.sleep(1)

        start_timestamp = time.time()
        result = start_ct201(f"PRF: {prf_algorithms[i]}", LAST_KNOWN_GOOD)
        end_timestamp = time.time()
        duration = round(end_timestamp - start_timestamp, 2)
        
        list_of_prfs.append([prf_algorithms[i], result, duration])
    
    with open(PARAM_PATH, "w") as new_config_xml:
        new_config_xml.write(LAST_KNOWN_GOOD)

    print("Finished testing all pseudo random functions.\n")
    return list_of_prfs

def test_all_enc(LAST_KNOWN_GOOD: str):
    print("Testing all encryption algorithms...")

    list_of_encs = []
    with open(PARAM_PATH, "r") as config_xml:
            current_xml = config_xml.read()
    if not LAST_KNOWN_GOOD: LAST_KNOWN_GOOD = current_xml

    for i in range(len(encryption_algorithms)):
        current_xml = LAST_KNOWN_GOOD
        pos = current_xml.find('<parameter id="CIPHER_IKE_SA_ENCRYPTION">') + 62
        current_xml_start = current_xml[:pos]
        current_xml_end = current_xml[pos:]
        pos2 = current_xml_end.find("</string>")
        current_xml_end = current_xml_end[pos2:]
        current_xml = current_xml_start + encryption_algorithms[i] + current_xml_end

        with open(PARAM_PATH, "w") as new_config_xml:
            new_config_xml.write(current_xml)

        time.sleep(1)

        start_timestamp = time.time()
        result = start_ct201(f"ENC: {encryption_algorithms[i]}", LAST_KNOWN_GOOD)
        end_timestamp = time.time()
        duration = round(end_timestamp - start_timestamp, 2)

        list_of_encs.append([encryption_algorithms[i], result, duration])
    
    with open(PARAM_PATH, "w") as new_config_xml:
        new_config_xml.write(LAST_KNOWN_GOOD)

    print("Finished testing all encryption algorithms.\n")
    return list_of_encs

""" Main """
if __name__ == '__main__':
    LAST_KNOWN_GOOD = 0

    start_timestamp = time.time()

    with open(PARAM_PATH, "r") as config_xml:
            current_xml = config_xml.read()
    if not LAST_KNOWN_GOOD: LAST_KNOWN_GOOD = current_xml

    print("Test initial connection...")
    s = start_ct201("Test initial connection", LAST_KNOWN_GOOD)
    if not s: exit("Error: Initial connection was not successful!")

    a_single = test_all_auth_single(LAST_KNOWN_GOOD)
    a_double = test_all_auth(LAST_KNOWN_GOOD)
    #p = test_all_prf(LAST_KNOWN_GOOD)
    #e = test_all_enc(LAST_KNOWN_GOOD)
    #d = test_all_dh_groups(LAST_KNOWN_GOOD)

    print("Test final connection...")
    s = start_ct201("Test final connection", LAST_KNOWN_GOOD)
    if not s: exit("Error: Final connection was not successful!")

    with open(PARAM_PATH, "w") as new_config_xml:
        new_config_xml.write(LAST_KNOWN_GOOD)
    
    end_timestamp = time.time()
    duration = round(end_timestamp - start_timestamp, 2)

    all_reports = a_single + a_double #+ p + e + d
    all_reports.append(duration)

    with open("C:/Users/Laptop/Desktop/Achelos/report.txt", "w") as report:
        for rep in all_reports:
            report.write(str(rep) + "\n")

    exit()