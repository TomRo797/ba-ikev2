import glob
import os
from parse_pcap import ISAKMP_Parser
from contextlib import redirect_stdout # Source: https://stackoverflow.com/questions/7152762/how-to-redirect-print-output-to-a-file at 22.08.2024

class Analyzer:
    """ ATTRIBUTES """
    LOG_PATH = str

    """ CONSTRUCTOR """
    def __init__(self, path_to_logs: str) -> None:
        self.LOG_PATH = path_to_logs

    """ METHODS """
    def analyze(self):
        res_con = self.analyze_connectivityTest()
        res_consistency = self.analyze_consitencyDHTest()
        res_auth = self.analyze_auth()
        res_rekeying = self.analyze_rekeying()
        res_reauth = self.analyze_reauth()

        c = 0
        print(" ")

        if res_con != "PASSED": print(f"Connectivity test: FAILED!!!\nReturn value: {res_con}\n")
        else: 
            c += 1
            print("Connectivity test: PASSED!")
        if res_consistency != "PASSED": print(f"Consistency DH test: FAILED!!!\nReturn value: {res_consistency}\n")
        else: 
            c += 1
            print("Consistency DH test: PASSED!")
        if res_auth != "PASSED": print(f"Authenticity test: FAILED!!!\nReturn value: {res_auth}\n")
        else: 
            c += 1
            print("Authenticity test: PASSED!")
        if res_rekeying != "PASSED": print(f"Rekeying test: FAILED!!!\nReturn value: {res_rekeying}\n")
        else: 
            c += 1
            print("Rekeying test: PASSED!")
        if res_reauth != "PASSED": print(f"Reauthentication test: FAILED!!!\nReturn value: {res_reauth}")
        else: 
            c += 1
            print("Reauthentication test: PASSED!")

        print(f"\n{c} out of 5 test cases passed!")

    def analyze_connectivityTest(self) -> str:
        all_pcaps = glob.glob(self.LOG_PATH + "*ConnectivityTesting_2*.pcap")
        pcap_file = max(all_pcaps, key=os.path.getmtime)

        parser = ISAKMP_Parser(pcap_file)
        with open(self.LOG_PATH + "CT2-01_PCAP_PARSED.txt", "w") as f:
            with redirect_stdout(f):
                parser.parse()

        parsed_packets = []
        with open(self.LOG_PATH + "CT2-01_PCAP_PARSED.txt", "r") as f:
            parsed_packets = f.read()
        
        packet_count_pos = parsed_packets.find("Parsed ISAKMP packets: ")
        packet_count = parsed_packets[packet_count_pos+23:]
        if packet_count[1] != " ": packet_count = int(packet_count[:2])
        else: packet_count = int(packet_count[:1])

        packets = []
        for i in range(1, packet_count+1):
            pos_begin = parsed_packets.find(f"#################### PACKET {i} BEGIN ####################")
            pos_end = parsed_packets.find(f"#################### PACKET {i} END ####################")
            single_packet = parsed_packets[pos_begin+57:pos_end]
            packets.append(single_packet)
        
        """ CHECK PCAP """
        print("Check PCAP CT2-01...")
        # Check packet 1
        if packets[0].find("Source IP: 10.0.71.3") < 0: return "ERR PACKET 1: Source IP"
        if packets[0].find("Destination IP: 10.0.71.4") < 0: return "ERR PACKET 1: Destination IP"
        if packets[0].find("Proposal Transforms: 3") < 0: return "ERR PACKET 1: Number of transforms"
        if packets[0].find("Next Payload: Security Association (33)") < 0: return "ERR PACKET 1: Next payload"
        if packets[0].find("Exchange Type: IKE_SA_INIT (34)") < 0: return "ERR PACKET 1: Exchange type"
        if packets[0].find("Initiator") < 0: return "ERR PACKET 1: Initiator"
        if packets[0].find("Protocol ID: IKE (1)") < 0: return "ERR PACKET 1: Protocol id"
        if packets[0].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return "ERR PACKET 1: Encryption algorithm"
        if packets[0].find("Key Length: 256") < 0: return "ERR PACKET 1: Encryption algorithm key length"
        if packets[0].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return "ERR PACKET 1: PRF transform"
        if packets[0].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return "ERR PACKET 1: PRF algorithm"
        if packets[0].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return "ERR PACKET 1: DH tranform"
        if packets[0].find("Transform ID: brainpoolP512r1 (30)") < 0: return "ERR PACKET 1: DH-Group"

        # Check packet 2
        if packets[1].find("Source IP: 10.0.71.4") < 0: return "ERR PACKET 2: Source IP"
        if packets[1].find("Destination IP: 10.0.71.3") < 0: return "ERR PACKET 2: Destination IP"
        if packets[1].find("Proposal Transforms: 3") < 0: return "ERR PACKET 2: Number of transforms"
        if packets[1].find("Next Payload: Security Association (33)") < 0: return "ERR PACKET 2: Next payload"
        if packets[1].find("Exchange Type: IKE_SA_INIT (34)") < 0: return "ERR PACKET 2: Exchange type"
        if packets[1].find("Responder") < 0: return "ERR PACKET 2: Responder"
        if packets[1].find("Protocol ID: IKE (1)") < 0: return "ERR PACKET 2: Protocol id"
        if packets[1].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return "ERR PACKET 2: Encryption algorithm"
        if packets[1].find("Key Length: 256") < 0: return "ERR PACKET 2: Encryption algorithm key length"
        if packets[1].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return "ERR PACKET 2: PRF transform"
        if packets[1].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return "ERR PACKET 2: PRF algorithm"
        if packets[1].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return "ERR PACKET 2: DH tranform"
        if packets[1].find("Transform ID: brainpoolP512r1 (30)") < 0: return "ERR PACKET 2: DH-Group"

        # Check packet 3
        if packets[2].find("Source IP: 10.0.71.3") < 0: return "ERR PACKET 3: Source IP"
        if packets[2].find("Destination IP: 10.0.71.4") < 0: return "ERR PACKET 3: Destination IP"
        if packets[2].find("Next Payload: Encrypted and Authenticated (46)") < 0: return "ERR PACKET 3: Next payload"
        if packets[2].find("Exchange Type: IKE_AUTH (35)") < 0: return "ERR PACKET 3: Exchange type"
        if packets[2].find("Initiator") < 0: return "ERR PACKET 3: Initiator"
        if packets[2].find("Message ID: 00000001") < 0: return "ERR PACKET 3: Message id"
        if packets[2].find("Next Payload: Identification - Initiator (35)") < 0: return "ERR PACKET 3: Next payload - identification"

        # Check packet 4
        if packets[3].find("Source IP: 10.0.71.4") < 0: return "ERR PACKET 4: Source IP"
        if packets[3].find("Destination IP: 10.0.71.3") < 0: return "ERR PACKET 4: Destination IP"
        if packets[3].find("Next Payload: Encrypted and Authenticated (46)") < 0: return "ERR PACKET 4: Next payload"
        if packets[3].find("Exchange Type: IKE_AUTH (35)") < 0: return "ERR PACKET 4: Exchange type"
        if packets[3].find("Responder") < 0: return "ERR PACKET 4: Initiator"
        if packets[3].find("Message ID: 00000001") < 0: return "ERR PACKET 4: Message id"
        if packets[3].find("Next Payload: Identification - Responder (36)") < 0: return "ERR PACKET 4: Next payload - identification"

        # Check packet 5
        if packets[4].find("Source IP: 10.0.71.3") < 0: return "ERR PACKET 5: Source IP"
        if packets[4].find("Destination IP: 10.0.71.4") < 0: return "ERR PACKET 5: Destination IP"
        if packets[4].find("Next Payload: Encrypted and Authenticated (46)") < 0: return "ERR PACKET 5: Next payload"
        if packets[4].find("Exchange Type: IKE_AUTH (35)") < 0: return "ERR PACKET 5: Exchange type"
        if packets[4].find("Initiator") < 0: return "ERR PACKET 5: Initiator"
        if packets[4].find("Message ID: 00000002") < 0: return "ERR PACKET 5: Message id"
        if packets[4].find("Next Payload: Identification - Initiator (35)") < 0: return "ERR PACKET 5: Next payload - identification"

        # Check packet 6
        if packets[5].find("Source IP: 10.0.71.4") < 0: return "ERR PACKET 6: Source IP"
        if packets[5].find("Destination IP: 10.0.71.3") < 0: return "ERR PACKET 6: Destination IP"
        if packets[5].find("Next Payload: Encrypted and Authenticated (46)") < 0: return "ERR PACKET 6: Next payload"
        if packets[5].find("Exchange Type: IKE_AUTH (35)") < 0: return "ERR PACKET 6: Exchange type"
        if packets[5].find("Responder") < 0: return "ERR PACKET 6: Initiator"
        if packets[5].find("Message ID: 00000002") < 0: return "ERR PACKET 6: Message id"
        if packets[5].find("Next Payload: Identification - Responder (36)") < 0: return "ERR PACKET 6: Next payload - identification"

        print("ok")

        """ CHECK TRUSTED CHANNEL LOG """
        all_tclogs = glob.glob(self.LOG_PATH + "*ConnectivityTesting_2*TC*.log")
        tclog = max(all_tclogs, key=os.path.getmtime)

        parsed_tclog = str
        with open(tclog, "r") as f:
            parsed_tclog = f.read()

        print("Check TC Log CT2-01...")
        if parsed_tclog.find("ikev2_pld_id: id ASN1_DN//serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC") < 0: return "ERR TC LOG: ikev2_pld_id"
        if parsed_tclog.find("ikev2_pld_cert: type X509_CERT") < 0: return "ERR TC LOG: ikev2_pld_cert"
        if parsed_tclog.find("sa_stateok: AUTH_REQUEST -> AUTH_REQUEST OK") < 0: return "ERR TC LOG: AUTH_REQUEST"
        if parsed_tclog.find("ca_getreq: found CA /CN=TVPNC-CA/O=System Test/L=K\\xC3\\xB6ln/ST=NRW/C=DE") < 0: return "ERR TC LOG: ca_getreq"
        if parsed_tclog.find("ca_validate_cert: /serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC ok") < 0: return "ERR TC LOG: ca_validate_cert"

        print("ok")

        """ TEST CASE PASSED - ANALNYZED WITHOUT ERRORS FOUND """
        return "PASSED"

    def analyze_consitencyDHTest(self):
        all_pcaps = glob.glob(self.LOG_PATH + "*AVA_Pen_3*.pcap")
        pcap_file = max(all_pcaps, key=os.path.getmtime)

        parser = ISAKMP_Parser(pcap_file)
        with open(self.LOG_PATH + "AVA_Pen_3-02_PCAP_PARSED.txt", "w") as f:
            with redirect_stdout(f):
                parser.parse()

        parsed_packets = []
        with open(self.LOG_PATH + "AVA_Pen_3-02_PCAP_PARSED.txt", "r") as f:
            parsed_packets = f.read()
        
        packet_count_pos = parsed_packets.find("Parsed ISAKMP packets: ")
        packet_count = parsed_packets[packet_count_pos+23:]
        if packet_count[1] != " ": packet_count = int(packet_count[:2])
        else: packet_count = int(packet_count[:1])

        if packet_count > 2: return "ERR PACKET COUNT: More then two packets found"

        packets = []
        for i in range(1, packet_count+1):
            pos_begin = parsed_packets.find(f"#################### PACKET {i} BEGIN ####################")
            pos_end = parsed_packets.find(f"#################### PACKET {i} END ####################")
            single_packet = parsed_packets[pos_begin+57:pos_end]
            packets.append(single_packet)
        
        """ CHECK PCAP """
        print("Check PCAP AVA_Pen3_01...")
        # Check packet 1
        if packets[0].find("Source IP: 10.0.71.3") < 0: return "ERR PACKET 1: Source IP"
        if packets[0].find("Destination IP: 10.0.71.4") < 0: return "ERR PACKET 1: Destination IP"
        if packets[0].find("Proposal Transforms: 3") < 0: return "ERR PACKET 1: Number of transforms"
        if packets[0].find("Next Payload: Security Association (33)") < 0: return "ERR PACKET 1: Next payload"
        if packets[0].find("Exchange Type: IKE_SA_INIT (34)") < 0: return "ERR PACKET 1: Exchange type"
        if packets[0].find("Initiator") < 0: return "ERR PACKET 1: Initiator"
        if packets[0].find("Protocol ID: IKE (1)") < 0: return "ERR PACKET 1: Protocol id"
        if packets[0].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return "ERR PACKET 1: Encryption algorithm"
        if packets[0].find("Key Length: 256") < 0: return "ERR PACKET 1: Encryption algorithm key length"
        if packets[0].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return "ERR PACKET 1: PRF transform"
        if packets[0].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return "ERR PACKET 1: PRF algorithm"
        if packets[0].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return "ERR PACKET 1: DH tranform"
        if packets[0].find("Transform ID: brainpoolP512r1 (30)") < 0: return "ERR PACKET 1: DH-Group"

        # Check packet 2
        if packets[1].find("Source IP: 10.0.71.4") < 0: return "ERR PACKET 2: Source IP"
        if packets[1].find("Destination IP: 10.0.71.3") < 0: return "ERR PACKET 2: Destination IP"
        if packets[1].find("Proposal Transforms: 3") < 0: return "ERR PACKET 2: Number of transforms"
        if packets[1].find("Next Payload: Security Association (33)") < 0: return "ERR PACKET 2: Next payload"
        if packets[1].find("Exchange Type: IKE_SA_INIT (34)") < 0: return "ERR PACKET 2: Exchange type"
        if packets[1].find("Responder") < 0: return "ERR PACKET 2: Responder"
        if packets[1].find("Protocol ID: IKE (1)") < 0: return "ERR PACKET 2: Protocol id"
        if packets[1].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return "ERR PACKET 2: Encryption algorithm"
        if packets[1].find("Key Length: 256") < 0: return "ERR PACKET 2: Encryption algorithm key length"
        if packets[1].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return "ERR PACKET 2: PRF transform"
        if packets[1].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return "ERR PACKET 2: PRF algorithm"
        if packets[1].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return "ERR PACKET 2: DH tranform"
        if packets[1].find("Transform ID: brainpoolP224r1 (27)") < 0: return "ERR PACKET 2: DH-Group brainpoolP224r1 (27) was not found"

        print("ok")

        """ CHECK TRUSTED CHANNEL LOG """
        all_tclogs = glob.glob(self.LOG_PATH + "*AVA_Pen_3-02*TC*.log")
        tclog = max(all_tclogs, key=os.path.getmtime)

        parsed_tclog = str
        with open(tclog, "r") as f:
            parsed_tclog = f.read()

        print("Check TC Log AVA_Pen3_01...")
        if parsed_tclog.find("ikev2_pld_xform: more 0 reserved 0 length 8 type DH id BRAINPOOL_P512R1") < 0: return "ERR TC LOG: ikev2_pld_xform"
        if parsed_tclog.find("ikev2_pld_ke: dh group BRAINPOOL_P512R1 reserved 0") < 0: return "ERR TC LOG: ikev2_pld_ke"
        if parsed_tclog.find("proposals_negotiate: score 4: ENCR AES_GCM_16 256") < 0: return "ERR TC LOG: Encryption algorithm proposal"
        if parsed_tclog.find("proposals_negotiate: score 3: PRF HMAC_SHA2_512") < 0: return "ERR TC LOG: PRF algorithm proposal"
        if parsed_tclog.find("proposals_negotiate: score 1: DH BRAINPOOL_P512R1") < 0: return "ERR TC LOG: DH group proposal"
        if parsed_tclog.find("sa_stateok: SA_INIT -> SA_INIT OK") < 0: return "ERR TC LOG: sa_state nok"
        if parsed_tclog.find("manipulate_sa_proposals: Diffie-Hellman group in SA payload of IKE_SA_INIT response will be replaced by 27") < 0: return "ERR TC LOG: Manipulation of sa proposals"
        if parsed_tclog.find("ikev2_add_transform: type: DH, id: 27") < 0: return "ERR TC LOG: Transform not added"
        if parsed_tclog.find("ikev2_pld_xform: more 0 reserved 0 length 8 type DH id BRAINPOOL_P224R1") < 0: return "ERR TC LOG: ikev2_pld_xform responder"
        if parsed_tclog.find("sa_stateok: AUTH_REQUEST -> AUTH_REQUEST OK") > 0: return "ERR TC LOG: AUTH_REQUEST received"
        if parsed_tclog.find("ca_validate_cert: /serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC ok") > 0: return "ERR TC LOG: ca_validate_cert received"

        print("ok")

        """ TEST CASE PASSED - ANALNYZED WITHOUT ERRORS FOUND """
        return "PASSED"

    def analyze_auth(self) -> str:
        all_pcaps = glob.glob(self.LOG_PATH + "*AVA_Pen_4-01*.pcap")
        pcap_file = max(all_pcaps, key=os.path.getmtime)

        parser = ISAKMP_Parser(pcap_file)
        with open(self.LOG_PATH + "AVA_Pen_4-01_PCAP_PARSED.txt", "w") as f:
            with redirect_stdout(f):
                parser.parse()

        parsed_packets = []
        with open(self.LOG_PATH + "AVA_Pen_4-01_PCAP_PARSED.txt", "r") as f:
            parsed_packets = f.read()
        
        packet_count_pos = parsed_packets.find("Parsed ISAKMP packets: ")
        packet_count = parsed_packets[packet_count_pos+23:]
        if packet_count[1] != " ": packet_count = int(packet_count[:2])
        else: packet_count = int(packet_count[:1])

        if packet_count != 16: return "ERR PACKET COUNT: Packet count not 16"

        packets = []
        for i in range(1, packet_count+1):
            pos_begin = parsed_packets.find(f"#################### PACKET {i} BEGIN ####################")
            pos_end = parsed_packets.find(f"#################### PACKET {i} END ####################")
            single_packet = parsed_packets[pos_begin+57:pos_end]
            packets.append(single_packet)
        
        """ CHECK PCAP """
        print("Check PCAP AVA_Pen4-01...")
        # Check packet 1
        if packets[0].find("Source IP: 10.0.71.3") < 0: return "ERR PACKET 1: Source IP"
        if packets[0].find("Destination IP: 10.0.71.4") < 0: return "ERR PACKET 1: Destination IP"
        if packets[0].find("Proposal Transforms: 3") < 0: return "ERR PACKET 1: Number of transforms"
        if packets[0].find("Next Payload: Security Association (33)") < 0: return "ERR PACKET 1: Next payload"
        if packets[0].find("Exchange Type: IKE_SA_INIT (34)") < 0: return "ERR PACKET 1: Exchange type"
        if packets[0].find("Initiator") < 0: return "ERR PACKET 1: Initiator"
        if packets[0].find("Protocol ID: IKE (1)") < 0: return "ERR PACKET 1: Protocol id"
        if packets[0].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return "ERR PACKET 1: Encryption algorithm"
        if packets[0].find("Key Length: 256") < 0: return "ERR PACKET 1: Encryption algorithm key length"
        if packets[0].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return "ERR PACKET 1: PRF transform"
        if packets[0].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return "ERR PACKET 1: PRF algorithm"
        if packets[0].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return "ERR PACKET 1: DH tranform"
        if packets[0].find("Transform ID: brainpoolP512r1 (30)") < 0: return "ERR PACKET 1: DH-Group"

        # Check packet 2
        if packets[1].find("Source IP: 10.0.71.4") < 0: return "ERR PACKET 2: Source IP"
        if packets[1].find("Destination IP: 10.0.71.3") < 0: return "ERR PACKET 2: Destination IP"
        if packets[1].find("Proposal Transforms: 3") < 0: return "ERR PACKET 2: Number of transforms"
        if packets[1].find("Next Payload: Security Association (33)") < 0: return "ERR PACKET 2: Next payload"
        if packets[1].find("Exchange Type: IKE_SA_INIT (34)") < 0: return "ERR PACKET 2: Exchange type"
        if packets[1].find("Responder") < 0: return "ERR PACKET 2: Responder"
        if packets[1].find("Protocol ID: IKE (1)") < 0: return "ERR PACKET 2: Protocol id"
        if packets[1].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return "ERR PACKET 2: Encryption algorithm"
        if packets[1].find("Key Length: 256") < 0: return "ERR PACKET 2: Encryption algorithm key length"
        if packets[1].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return "ERR PACKET 2: PRF transform"
        if packets[1].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return "ERR PACKET 2: PRF algorithm"
        if packets[1].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return "ERR PACKET 2: DH tranform"
        if packets[1].find("Transform ID: brainpoolP512r1 (30)") < 0: return "ERR PACKET 2: DH-Group"

        for i in range(3, packet_count+1):
            if i % 2:
                # Check packets 3, 5, 7, 9, 11, 13, 15
                if packets[i-1].find("Source IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.4") < 0: return  f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return  f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: IKE_AUTH (35)") < 0: return  f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Initiator") < 0: return  f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Message ID: 00000001") < 0: return  f"ERR PACKET {i}: Message id"
                if packets[i-1].find("Next Payload: Identification - Initiator (35)") < 0: return  f"ERR PACKET {i}: Next payload - identification"
            else:
                # Check packets 4, 6, 8, 10, 12, 14, 16
                if packets[i-1].find("Source IP: 10.0.71.4") < 0: return  f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.3") < 0: return  f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") > 0: return  f"ERR PACKET {i}: Next payload encrypted"
                if packets[i-1].find("Next Payload: Identification - Responder (36)") < 0: return  f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: IKE_AUTH (35)") < 0: return  f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Responder") < 0: return  f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Message ID: 00000001") < 0: return  f"ERR PACKET {i}: Message id"
                if packets[i-1].find("Next Payload: Certificate (37)") < 0: return  f"ERR PACKET {i}: Next payload - certificate"
                if packets[i-1].find("Notify Message Type: ANOTHER_AUTH_FOLLOWS (16405)") < 0: return  f"ERR PACKET {i}: Nofify message type"

        print("ok")

        """ CHECK TRUSTED CHANNEL LOG """
        all_tclogs = glob.glob(self.LOG_PATH + "*AVA_Pen_4-01*TC*.log")
        tclog = max(all_tclogs, key=os.path.getmtime)

        parsed_tclog = str
        with open(tclog, "r") as f:
            parsed_tclog = f.read()

        print("Check TC Log AVA_Pen4-01...")
        if parsed_tclog.find("sa_stateok: SA_INIT -> SA_INIT OK") < 0: return "ERR TC LOG: IKE SA nok"
        if parsed_tclog.find("et_manipulate_resp_ike_auth_no_encrypt: Do not encrypt IKE_AUTH response") < 0: return "ERR TC LOG: Manipulate IKE AUTH repsonse"
        if parsed_tclog.find("sendtofrom: Message ID: 1") < 0: return "ERR TC LOG: Message ID"
        if parsed_tclog.find("sendtofrom: Message ID: 2") > 0: return "ERR TC LOG: Message ID 2 received"
        if parsed_tclog.find("ikev2_pld_id: id ASN1_DN//serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC") < 0: return "ERR TC LOG: ikev2_pld_id"
        if parsed_tclog.find("ikev2_pld_cert: type X509_CERT") < 0: return "ERR TC LOG: ikev2_pld_cert"
        if parsed_tclog.find("sa_stateok: AUTH_REQUEST -> AUTH_REQUEST OK") < 0: return "ERR TC LOG: AUTH_REQUEST"
        if parsed_tclog.find("ca_getreq: found CA /CN=TVPNC-CA/O=System Test/L=K\\xC3\\xB6ln/ST=NRW/C=DE") < 0: return "ERR TC LOG: ca_getreq"
        if parsed_tclog.find("ca_validate_cert: /serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC ok") < 0: return "ERR TC LOG: ca_validate_cert"

        print("ok")

        return "PASSED"

    def analyze_rekeying(self) -> str:
        all_pcaps = glob.glob(self.LOG_PATH + "*RFC7296_Kp.2.17_1-01*.pcap")
        pcap_file = max(all_pcaps, key=os.path.getmtime)

        parser = ISAKMP_Parser(pcap_file)
        with open(self.LOG_PATH + "RFC7296_Kp.2.17_1-01_PCAP_PARSED.txt", "w") as f:
            with redirect_stdout(f):
                parser.parse()

        parsed_packets = []
        with open(self.LOG_PATH + "RFC7296_Kp.2.17_1-01_PCAP_PARSED.txt", "r") as f:
            parsed_packets = f.read()
        
        packet_count_pos = parsed_packets.find("Parsed ISAKMP packets: ")
        packet_count = parsed_packets[packet_count_pos+23:]
        if packet_count[1] != " ": 
            if packet_count[2] != " ": packet_count = int(packet_count[:3])
            else: packet_count = int(packet_count[:2])
        else: packet_count = int(packet_count[:1])

        if packet_count < 6: return "ERR PACKET COUNT: Packet count less then 6"

        packets = []
        for i in range(1, packet_count+1):
            pos_begin = parsed_packets.find(f"#################### PACKET {i} BEGIN ####################")
            pos_end = parsed_packets.find(f"#################### PACKET {i} END ####################")
            single_packet = parsed_packets[pos_begin+57:pos_end]
            packets.append(single_packet)
        
        """ CHECK PCAP """
        print("Check PCAP RFC7296_Kp2.17_1-01...")

         # Check packet 1
        if packets[0].find("Source IP: 10.0.71.3") < 0: return "ERR PACKET 1: Source IP"
        if packets[0].find("Destination IP: 10.0.71.4") < 0: return "ERR PACKET 1: Destination IP"
        if packets[0].find("Proposal Transforms: 3") < 0: return "ERR PACKET 1: Number of transforms"
        if packets[0].find("Next Payload: Security Association (33)") < 0: return "ERR PACKET 1: Next payload"
        if packets[0].find("Exchange Type: IKE_SA_INIT (34)") < 0: return "ERR PACKET 1: Exchange type"
        if packets[0].find("Initiator") < 0: return "ERR PACKET 1: Initiator"
        if packets[0].find("Protocol ID: IKE (1)") < 0: return "ERR PACKET 1: Protocol id"
        if packets[0].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return "ERR PACKET 1: Encryption algorithm"
        if packets[0].find("Key Length: 256") < 0: return "ERR PACKET 1: Encryption algorithm key length"
        if packets[0].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return "ERR PACKET 1: PRF transform"
        if packets[0].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return "ERR PACKET 1: PRF algorithm"
        if packets[0].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return "ERR PACKET 1: DH tranform"
        if packets[0].find("Transform ID: brainpoolP512r1 (30)") < 0: return "ERR PACKET 1: DH-Group"

        # Check packet 2
        if packets[1].find("Source IP: 10.0.71.4") < 0: return "ERR PACKET 2: Source IP"
        if packets[1].find("Destination IP: 10.0.71.3") < 0: return "ERR PACKET 2: Destination IP"
        if packets[1].find("Proposal Transforms: 3") < 0: return "ERR PACKET 2: Number of transforms"
        if packets[1].find("Next Payload: Security Association (33)") < 0: return "ERR PACKET 2: Next payload"
        if packets[1].find("Exchange Type: IKE_SA_INIT (34)") < 0: return "ERR PACKET 2: Exchange type"
        if packets[1].find("Responder") < 0: return "ERR PACKET 2: Responder"
        if packets[1].find("Protocol ID: IKE (1)") < 0: return "ERR PACKET 2: Protocol id"
        if packets[1].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return "ERR PACKET 2: Encryption algorithm"
        if packets[1].find("Key Length: 256") < 0: return "ERR PACKET 2: Encryption algorithm key length"
        if packets[1].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return "ERR PACKET 2: PRF transform"
        if packets[1].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return "ERR PACKET 2: PRF algorithm"
        if packets[1].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return "ERR PACKET 2: DH tranform"
        if packets[1].find("Transform ID: brainpoolP512r1 (30)") < 0: return "ERR PACKET 2: DH-Group"

        # Check packet 3
        if packets[2].find("Source IP: 10.0.71.3") < 0: return "ERR PACKET 3: Source IP"
        if packets[2].find("Destination IP: 10.0.71.4") < 0: return "ERR PACKET 3: Destination IP"
        if packets[2].find("Next Payload: Encrypted and Authenticated (46)") < 0: return "ERR PACKET 3: Next payload"
        if packets[2].find("Exchange Type: IKE_AUTH (35)") < 0: return "ERR PACKET 3: Exchange type"
        if packets[2].find("Initiator") < 0: return "ERR PACKET 3: Initiator"
        if packets[2].find("Message ID: 00000001") < 0: return "ERR PACKET 3: Message id"
        if packets[2].find("Next Payload: Identification - Initiator (35)") < 0: return "ERR PACKET 3: Next payload - identification"

        # Check packet 4
        if packets[3].find("Source IP: 10.0.71.4") < 0: return "ERR PACKET 4: Source IP"
        if packets[3].find("Destination IP: 10.0.71.3") < 0: return "ERR PACKET 4: Destination IP"
        if packets[3].find("Next Payload: Encrypted and Authenticated (46)") < 0: return "ERR PACKET 4: Next payload"
        if packets[3].find("Exchange Type: IKE_AUTH (35)") < 0: return "ERR PACKET 4: Exchange type"
        if packets[3].find("Responder") < 0: return "ERR PACKET 4: Initiator"
        if packets[3].find("Message ID: 00000001") < 0: return "ERR PACKET 4: Message id"
        if packets[3].find("Next Payload: Identification - Responder (36)") < 0: return "ERR PACKET 4: Next payload - identification"

        # Check packet 5
        if packets[4].find("Source IP: 10.0.71.3") < 0: return "ERR PACKET 5: Source IP"
        if packets[4].find("Destination IP: 10.0.71.4") < 0: return "ERR PACKET 5: Destination IP"
        if packets[4].find("Next Payload: Encrypted and Authenticated (46)") < 0: return "ERR PACKET 5: Next payload"
        if packets[4].find("Exchange Type: IKE_AUTH (35)") < 0: return "ERR PACKET 5: Exchange type"
        if packets[4].find("Initiator") < 0: return "ERR PACKET 5: Initiator"
        if packets[4].find("Message ID: 00000002") < 0: return "ERR PACKET 5: Message id"
        if packets[4].find("Next Payload: Identification - Initiator (35)") < 0: return "ERR PACKET 5: Next payload - identification"

        # Check packet 6
        if packets[5].find("Source IP: 10.0.71.4") < 0: return "ERR PACKET 6: Source IP"
        if packets[5].find("Destination IP: 10.0.71.3") < 0: return "ERR PACKET 6: Destination IP"
        if packets[5].find("Next Payload: Encrypted and Authenticated (46)") < 0: return "ERR PACKET 6: Next payload"
        if packets[5].find("Exchange Type: IKE_AUTH (35)") < 0: return "ERR PACKET 6: Exchange type"
        if packets[5].find("Responder") < 0: return "ERR PACKET 6: Initiator"
        if packets[5].find("Message ID: 00000002") < 0: return "ERR PACKET 6: Message id"
        if packets[5].find("Next Payload: Identification - Responder (36)") < 0: return "ERR PACKET 6: Next payload - identification"

        mid = 3
        for i in range(7, packet_count+1):
            if (i-1) % 2 == 0:
                if int(mid) < 10: mid = f"0{mid}"
                else: mid = f"0{hex(mid)[2:]}"
                if i > 32: mid = hex(int(mid, 16))[2:]

                # Check packets INFORMATIONAL init
                if packets[i-1].find("Source IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: INFORMATIONAL (37)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Initiator") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find(f"Message ID: 000000{mid}") < 0: return f"ERR PACKET {i}: Message id {mid}"
                if packets[i-1].find("Next Payload: No Next Payload (0)") < 0: return f"ERR PACKET {i}: Next payload - no next payload"
            else:
                # Check packets INFORMATIONAL response
                if packets[i-1].find("Source IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: INFORMATIONAL (37)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Responder") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find(f"Message ID: 000000{mid}") < 0: return f"ERR PACKET {i}: Message id {mid}"
                if packets[i-1].find("Next Payload: No Next Payload (0)") < 0: return f"ERR PACKET {i}: Next payload - no next payload"

                mid = int(mid, 16) + 1

        print("ok")

        """ CHECK TRUSTED CHANNEL LOG """
        all_tclogs = glob.glob(self.LOG_PATH + "*RFC7296_Kp.2.17_1-01*TC*.log")
        tclog = max(all_tclogs, key=os.path.getmtime)

        parsed_tclog = str
        with open(tclog, "r") as f:
            parsed_tclog = f.read()

        print("Check TC Log RFC7296_Kp2.17_1-01...")
        if parsed_tclog.find("CREATE_CHILD_SA") > 0: return "ERR TC LOG: CREATE_CHILD_SA received"
        if parsed_tclog.find("sa_stateok: SA_INIT -> SA_INIT OK") < 0: return "ERR TC LOG: IKE SA nok"
        if parsed_tclog.find("sa_stateok: AUTH_SUCCESS -> AUTH_SUCCESS OK") < 0: return "ERR TC LOG: AUTH SUCCESS nok"
        if parsed_tclog.find("sendtofrom: Message ID: 1") < 0: return "ERR TC LOG: Message ID 1"
        if parsed_tclog.find("sendtofrom: Message ID: 2") < 0: return "ERR TC LOG: Message ID 2"
        if parsed_tclog.find("sendtofrom: Message ID: 3") < 0: return "ERR TC LOG: Message ID 3"
        if parsed_tclog.find("ikev2_pld_id: id ASN1_DN//serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC") < 0: return "ERR TC LOG: ikev2_pld_id"
        if parsed_tclog.find("ikev2_pld_cert: type X509_CERT") < 0: return "ERR TC LOG: ikev2_pld_cert"
        if parsed_tclog.find("sa_stateok: AUTH_REQUEST -> AUTH_REQUEST OK") < 0: return "ERR TC LOG: AUTH_REQUEST"
        if parsed_tclog.find("ca_getreq: found CA /CN=TVPNC-CA/O=System Test/L=K\\xC3\\xB6ln/ST=NRW/C=DE") < 0: return "ERR TC LOG: ca_getreq"
        if parsed_tclog.find("ca_validate_cert: /serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC ok") < 0: return "ERR TC LOG: ca_validate_cert"

        print("ok")

        return "PASSED"

    def analyze_reauth(self) -> str:
        all_pcaps = glob.glob(self.LOG_PATH + "*RFC7296_Kp.2.8_8-01*.pcap")
        pcap_file = max(all_pcaps, key=os.path.getmtime)

        parser = ISAKMP_Parser(pcap_file)
        with open(self.LOG_PATH + "RFC7296_Kp.2.8_8-01_PCAP_PARSED.txt", "w") as f:
            with redirect_stdout(f):
                parser.parse()

        parsed_packets = []
        with open(self.LOG_PATH + "RFC7296_Kp.2.8_8-01_PCAP_PARSED.txt", "r") as f:
            parsed_packets = f.read()
        
        packet_count_pos = parsed_packets.find("Parsed ISAKMP packets: ")
        packet_count = parsed_packets[packet_count_pos+23:]
        if packet_count[1] != " ": 
            if packet_count[2] != " ": packet_count = int(packet_count[:3])
            else: packet_count = int(packet_count[:2])
        else: packet_count = int(packet_count[:1])

        if packet_count < 100: return "ERR PACKET COUNT: Packet count less then 100"

        packets = []
        for i in range(1, packet_count+1):
            pos_begin = parsed_packets.find(f"#################### PACKET {i} BEGIN ####################")
            pos_end = parsed_packets.find(f"#################### PACKET {i} END ####################")
            single_packet = parsed_packets[pos_begin+57:pos_end]
            packets.append(single_packet)
        
        """ CHECK PCAP """
        print("Check PCAP RFC7296_Kp2.8_8-01...")

        for i in range(1, packet_count+1):
            if i-1 % 8 == 0:
                # Check packets SA init
                if packets[i-1].find("Source IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Proposal Transforms: 3") < 0: return f"ERR PACKET {i}: Number of transforms"
                if packets[i-1].find("Next Payload: Security Association (33)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: IKE_SA_INIT (34)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Initiator") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Protocol ID: IKE (1)") < 0: return f"ERR PACKET {i}: Protocol id"
                if packets[i-1].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return f"ERR PACKET {i}: Encryption algorithm"
                if packets[i-1].find("Key Length: 256") < 0: return f"ERR PACKET {i}: Encryption algorithm key length"
                if packets[i-1].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return f"ERR PACKET {i}: PRF transform"
                if packets[i-1].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return f"ERR PACKET {i}: PRF algorithm"
                if packets[i-1].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return f"ERR PACKET {i}: DH tranform"
                if packets[i-1].find("Transform ID: brainpoolP512r1 (30)") < 0: return f"ERR PACKET {i}: DH-Group"
            elif i-1 % 8 == 1:
                # Check packets SA reponse
                if packets[i-1].find("Source IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Proposal Transforms: 3") < 0: return f"ERR PACKET {i}: Number of transforms"
                if packets[i-1].find("Next Payload: Security Association (33)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: IKE_SA_INIT (34)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Responder") < 0: return f"ERR PACKET {i}: Responder"
                if packets[i-1].find("Protocol ID: IKE (1)") < 0: return f"ERR PACKET {i}: Protocol id"
                if packets[i-1].find("Transform ID: ENCR_AES_GCM_16 (20)") < 0: return f"ERR PACKET {i}: Encryption algorithm"
                if packets[i-1].find("Key Length: 256") < 0: return f"ERR PACKET {i}: Encryption algorithm key length"
                if packets[i-1].find("Transform Type: Pseudorandom Function (PRF) (2)") < 0: return f"ERR PACKET {i}: PRF transform"
                if packets[i-1].find("Transform ID: PRF_HMAC_SHA2_512 (7)") < 0: return f"ERR PACKET {i}: PRF algorithm"
                if packets[i-1].find("Transform Type: Diffie-Hellman Group (D-H) (4)") < 0: return f"ERR PACKET {i}: DH tranform"
                if packets[i-1].find("Transform ID: brainpoolP512r1 (30)") < 0: return f"ERR PACKET {i}: DH-Group"
            elif i-1 % 8 == 2:
                # Check packets AUTH 1 init 
                if packets[i-1].find("Source IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: IKE_AUTH (35)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Initiator") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Message ID: 00000001") < 0: return f"ERR PACKET {i}: Message id"
                if packets[i-1].find("Next Payload: Identification - Initiator (35)") < 0: return f"ERR PACKET {i}: Next payload - identification"
            elif i-1 % 8 == 3:
                # Check packets AUTH 1 reponse
                if packets[i-1].find("Source IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: IKE_AUTH (35)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Responder") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Message ID: 00000001") < 0: return f"ERR PACKET {i}: Message id"
                if packets[i-1].find("Next Payload: Identification - Responder (36)") < 0: return f"ERR PACKET {i}: Next payload - identification"
            elif i-1 % 8 == 4:
                # Check packets AUTH 2 init
                if packets[i-1].find("Source IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: IKE_AUTH (35)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Initiator") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Message ID: 00000002") < 0: return f"ERR PACKET {i}: Message id"
                if packets[i-1].find("Next Payload: Identification - Initiator (35)") < 0: return f"ERR PACKET {i}: Next payload - identification"
            elif i-1 % 8 == 5:
                # Check packets AUTH 2 reponse
                if packets[i-1].find("Source IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: IKE_AUTH (35)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Responder") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Message ID: 00000002") < 0: return f"ERR PACKET {i}: Message id"
                if packets[i-1].find("Next Payload: Identification - Responder (36)") < 0: return f"ERR PACKET {i}: Next payload - identification"
            elif i-1 % 8 == 6:
                # Check packets INFORMATIONAL init
                if packets[i-1].find("Source IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: INFORMATIONAL (37)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Initiator") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Message ID: 00000003") < 0: return f"ERR PACKET {i}: Message id"
                if packets[i-1].find("Next Payload: Delete (42)") < 0: return f"ERR PACKET {i}: Next payload - delete"
            elif i-1 % 8 == 7:
                # Check packets INFORMATIONAL reponse
                if packets[i-1].find("Source IP: 10.0.71.4") < 0: return f"ERR PACKET {i}: Source IP"
                if packets[i-1].find("Destination IP: 10.0.71.3") < 0: return f"ERR PACKET {i}: Destination IP"
                if packets[i-1].find("Next Payload: Encrypted and Authenticated (46)") < 0: return f"ERR PACKET {i}: Next payload"
                if packets[i-1].find("Exchange Type: INFORMATIONAL (37)") < 0: return f"ERR PACKET {i}: Exchange type"
                if packets[i-1].find("Responder") < 0: return f"ERR PACKET {i}: Initiator"
                if packets[i-1].find("Message ID: 00000003") < 0: return f"ERR PACKET {i}: Message id"
                if packets[i-1].find("Next Payload: No Next Payload (0)") < 0: return f"ERR PACKET {i}: Next payload - no next payload"

        print("ok")

        """ CHECK TRUSTED CHANNEL LOG """
        all_tclogs = glob.glob(self.LOG_PATH + "*RFC7296_Kp.2.8_8-01*TC*.log")
        tclog = max(all_tclogs, key=os.path.getmtime)

        parsed_tclog = str
        with open(tclog, "r") as f:
            parsed_tclog = f.read()

        print("Check TC Log RFC7296_Kp2.8_8-01...")
        if parsed_tclog.find("sa_stateok: SA_INIT -> SA_INIT OK") < 0: return "ERR TC LOG: IKE SA nok"
        if parsed_tclog.find("sa_stateok: AUTH_SUCCESS -> AUTH_SUCCESS OK") < 0: return "ERR TC LOG: AUTH SUCCESS nok"
        if parsed_tclog.find("sendtofrom: Message ID: 1") < 0: return "ERR TC LOG: Message ID 1"
        if parsed_tclog.find("sendtofrom: Message ID: 2") < 0: return "ERR TC LOG: Message ID 2"
        if parsed_tclog.find("sendtofrom: Message ID: 3") < 0: return "ERR TC LOG: Message ID 3"
        if parsed_tclog.find("manipulate_resp_ike_auth_add_auth_lifetime: Adding AUTH_LIFETIME notification to IKE_AUTH response") < 0: return "ERR TC LOG: set auth lifetime"
        if parsed_tclog.find("NOTIFY_TYPE = AUTH_LIFETIME NOTIFY_DATA = 00000014") < 0: return "ERR TC LOG: Auth lifetime not 20 seconds"
        if parsed_tclog.find("ikev2_pld_id: id ASN1_DN//serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC") < 0: return "ERR TC LOG: ikev2_pld_id"
        if parsed_tclog.find("ikev2_pld_cert: type X509_CERT") < 0: return "ERR TC LOG: ikev2_pld_cert"
        if parsed_tclog.find("sa_stateok: AUTH_REQUEST -> AUTH_REQUEST OK") < 0: return "ERR TC LOG: AUTH_REQUEST"
        if parsed_tclog.find("ca_getreq: found CA /CN=TVPNC-CA/O=System Test/L=K\\xC3\\xB6ln/ST=NRW/C=DE") < 0: return "ERR TC LOG: ca_getreq"
        if parsed_tclog.find("ca_validate_cert: /serialNumber=1166/emailAddress=achlos@rohde-schwarz.com/CN=Achelos/OU=Users/O=TVPNC ok") < 0: return "ERR TC LOG: ca_validate_cert"

        print("ok")

        return "PASSED"

# TESTING
if __name__ == '__main__':
    analyzer = Analyzer("C:/Users/tomro/Documents/Abschlussarbeit/Motivators/TestLogs/")
    analyzer.analyze()
    