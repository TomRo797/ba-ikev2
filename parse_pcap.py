"""
 TODO:
* ISAKMP Payload 49 - Subtype
* ISAKMP Payload 50
* ISAKMP Payload 51
* ISAKMP Payload 52
* ISAKMP Payload 53
* ISAKMP Payload 54
* Decrypt encrypted payloads
"""

""" Author: Tom Rodamer 11CENT - 04.08.2024 """
"""
SOURCES:
* RFCs: 4106, 5282, 5529, 7296, 8247
* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
* ChatGPT to create dictionaries out of tables
"""
from scapy.all import rdpcap
from binascii import unhexlify
import datetime

"""---------- ISAKMP SECTION BEGIN ----------"""

class ISAKMP_Parser:
    """ ATTRIBUTES """
    PATH = str
    CURRENT_ENCRYPTION_ALGORITHM = int
    PACKET_NUMBER = int
    IS_CURRENT_PACKET_INITIATOR = bool

    """ CONSTRUCTOR """
    def __init__(self, path_to_pcap: str) -> None:
        self.PATH = path_to_pcap
        self.PACKET_NUMBER = 0

    """ METHODS """
    # Print complete isakmp parsing
    def parse(self) -> None:
        # Execution time
        start_timestamp = datetime.datetime.now() 

        # Load the pcap file
        packets = rdpcap(self.PATH)

        # Filter ISAKMP-Packets (UDP-Port 500 and 4500)
        isakmp_packets = [pkt for pkt in packets if pkt.haslayer('UDP') and (pkt['UDP'].dport == 500 or pkt['UDP'].dport == 4500)]

        self.PACKET_NUMBER = len(isakmp_packets)

        # Analyse ISAKMP-Packets
        c = 1
        for packet in isakmp_packets:
            isakmp_data = bytes(packet['UDP'].payload)
            if isakmp_data.hex()[0:8] == "00000000": isakmp_data = isakmp_data[4:]
            print(f"#################### PACKET {c} BEGIN ####################")
            print(f'Source IP: {packet["IP"].src}')
            print(f'Destination IP: {packet["IP"].dst}')
            self.parse_isakmp(isakmp_data)
            print(f"#################### PACKET {c} END ####################\n\n")
            c += 1

        end_timestamp = datetime.datetime.now()
        print(f"\nParsed ISAKMP packets: {self.PACKET_NUMBER} packet(s) in {end_timestamp - start_timestamp}")

    # Get if current packet is initator or responder
    def isInitiator(self, payload: bytes) -> bool: # RFC 7296
        bits = self.byte_to_bit_list(payload)
        if bits[4] == 1: return True
        else: return False
    

    # Parse functions for ISAKMP
    def parse_isakmp(self, data: bytes) -> None: # RFC 7296
        if len(data) < 28:
            print("Invalid ISAKMP data")
            return

        initiator_spi = data[:8]
        responder_spi = data[8:16]
        next_payload = data[16]
        version = data[17]
        exchange_type = data[18]
        flags = data[19]
        message_id = data[20:24]
        length = int.from_bytes(data[24:28], "big")

        version_parse = self.split_byte_into_4bit_parts(version)
        print(f"Initiator SPI: {initiator_spi.hex()}")
        print(f"Responder SPI: {responder_spi.hex()}")
        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Version: {version_parse[0]}.{version_parse[1]}")
        print(f"Exchange Type: {self.parse_isakmp_header_exchange_type(exchange_type)}")
        print(f"Flags: {self.parse_isakmp_header_flags(flags)}")
        print(f"Message ID: {message_id.hex()}")
        print(f"Length: {length}")

        data = data[28:length]

        self.IS_CURRENT_PACKET_INITIATOR = self.isInitiator(flags)
        
        if next_payload != 0: self.parse_isakmp_payloads(data, next_payload)

    def parse_isakmp_payloads(self, data: bytes, next_payload: int) -> None: # RFC 7296
        if next_payload == 0: return None
        elif next_payload == 33: self.parse_isakmp_sa_payload(data) # Security Association
        elif next_payload == 34: self.parse_isakmp_kex_payload(data) # Key Exchange
        elif next_payload == 35: self.parse_isakmp_identification_payload(data, 0) # Identification Initiator
        elif next_payload == 36: self.parse_isakmp_identification_payload(data, 1) # Identification Responder
        elif next_payload == 37: self.parse_isakmp_cert_payload(data) # Certificate
        elif next_payload == 38: self.parse_isakmp_cert_request_payload(data) # Certificate Request
        elif next_payload == 39: self.parse_isakmp_authentication_payload(data) # Authentication
        elif next_payload == 40: self.parse_isakmp_nonce_payload(data) # Nonce
        elif next_payload == 41: self.parse_isakmp_notify_payload(data) # Notify
        elif next_payload == 42: self.parse_isakmp_delete_payload(data) # Delete
        elif next_payload == 43: self.parse_isakmp_vid_payload(data) # Vendor ID
        elif next_payload == 44: self.parse_isakmp_ts_payload(data, 44) # Traffic Selector Initiator
        elif next_payload == 45: self.parse_isakmp_ts_payload(data, 45) # Traffic Selector Responder
        elif next_payload == 46: self.parse_isakmp_encrypted_authenticated_payload(data) # Encrypted and Authenticated
        elif next_payload == 47: self.parse_isakmp_configuration_payload(data) # Configuration
        elif next_payload == 48: self.parse_isakmp_eap_payload(data) # EAP
        elif next_payload == 49: self.parse_isakmp_GSPM_payload(data) # Generic Secure Password Method
        elif next_payload == 50: return "Group Identification (50)" # TODO
        elif next_payload == 51: return "Group Security Association (51)" # TODO
        elif next_payload == 52: return "Key Download (52)" # TODO
        elif next_payload == 53: return "Encrypted and Authenticated Fragment (53)" # TODO
        elif next_payload == 54: return "Puzzle Solution (54)" # TODO
        else: return f"{next_payload}"#raise Exception("Next payload ID cannot be parsed!\nPayload parsed: " + str(next_payload) + " - this is not valid. Check RFC 7296 Section 3.2 and IANA-IKEv2 for valid payloads.")

    def parse_isakmp_next_payload(self, payload: bytes) -> str: # RFC 7296 & https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
        if payload == 0: return "No Next Payload (0)"
        elif payload == 33: return "Security Association (33)"
        elif payload == 34: return "Key Exchange (34)"
        elif payload == 35: return "Identification - Initiator (35)"
        elif payload == 36: return "Identification - Responder (36)"
        elif payload == 37: return "Certificate (37)"
        elif payload == 38: return "Certificate Request (38)"
        elif payload == 39: return "Authentication (39)"
        elif payload == 40: return "Nonce (40)"
        elif payload == 41: return "Notify (41)"
        elif payload == 42: return "Delete (42)"
        elif payload == 43: return "Vendor ID (43)"
        elif payload == 44: return "Traffic Selector - Initiator (44)"
        elif payload == 45: return "Traffic Selector - Responder (45)"
        elif payload == 46: return "Encrypted and Authenticated (46)"
        elif payload == 47: return "Configuration (47)"
        elif payload == 48: return "Extensible Authentication (48)"
        elif payload == 49: return "Generic Secure Password Method (49)"
        elif payload == 50: return "Group Identification (50)"
        elif payload == 51: return "Group Security Association (51)"
        elif payload == 52: return "Key Download (52)"
        elif payload == 53: return "Encrypted and Authenticated Fragment (53)"
        elif payload == 54: return "Puzzle Solution (54)"
        else: return f"{payload}"
        
    def parse_isakmp_header_exchange_type(self, payload: bytes) -> str: # RFC 7296
        if payload == 34: return "IKE_SA_INIT (34)"
        elif payload == 35: return "IKE_AUTH (35)"
        elif payload == 36: return "CREATE_CHILD_SA (36)"
        elif payload == 37: return "INFORMATIONAL (37)"
        elif payload == 38: return "IKE_SESSION_RESUME (38)"
        elif payload == 39: return "GSA_AUTH (39)"
        elif payload == 40: return "GSA_REGISTRATION (40)"
        elif payload == 41: return "GSA_REKEY (41)"
        elif payload == 43: return "IKE_INTERMEDIATE (43)"
        elif payload == 44: return "IKE_FOLLOWUP_KE (44)"
        else: return f"{payload}"

    def parse_isakmp_header_flags(self, payload: bytes) -> str: # RFC 7296
        bits = self.byte_to_bit_list(payload)
        ret = ""
        if bits[2] == 1: ret += "Response, "
        else: ret += "Request, "
        if bits[3] == 1: ret += "Higher version, "
        else: ret += "No higher version, "
        if bits[4] == 1: ret += "Initiator"
        else: ret += "Responder"
        return ret

    def parse_isakmp_critical_bit(self, bit: int) -> str: # RFC 7296
        if bit == 1: return "Critical"
        else: return "Not critical"


    # Parse functions for ISAKMP - Security Association
    def parse_isakmp_sa_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Security Association (33) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP Security Association data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved}")
        print(f"Length: {length}")

        proposal_data = data[4:length]
        if not proposal_data: print("--- PROPOSAL PARSE BEGIN ---\nNo proposal data received!\n--- PROPOSAL PARSE END ---")
        else: 
            more_proposals = self.parse_isakmp_sa_payload_proposal(proposal_data)
            if not more_proposals: pass
            else: self.parse_isakmp_sa_payload_proposal(data[4+more_proposals:])

        print("----- PAYLOAD PARSE END: Security Association (33) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)

    # Parse functions for ISAKMP - Security Association - Proposals
    def parse_isakmp_sa_payload_proposal(self, data: bytes) -> int: # RFC 7296
        print("\t--- PROPOSAL PARSE BEGIN ---")

        if len(data) < 8: raise Exception("Invalid ISAKMP SA Proposal data")
        last_substruc = data[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))
        length = int.from_bytes(data[2:4], "big")
        proposal_num = data[4]
        protocol_id = data[5]
        spi_size = data[6]
        num_transforms = data[7]
        if spi_size != 0: 
            spi = data[8:spi_size]
            transform_data = data[spi_size:]
        else: transform_data = data[8:]

        print(f"\tLast Proposal Substructre: {self.parse_isakmp_sa_payload_proposal_substruc(last_substruc)}")
        print(f"\tReserved Bits: {reserved}")
        print(f"\tLength: {length}")
        print(f"\tProposal Num: {proposal_num}")
        print(f"\tProtocol ID: {self.parse_isakmp_sa_payload_proposal_protocol_id(protocol_id)}")
        print(f"\tSPI Size: {spi_size}")
        print(f"\tProposal Transforms: {num_transforms}")
        if spi_size != 0: print(f"\tSPI: {spi}")
        if transform_data: self.parse_isakmp_sa_payload_proposal_transforms(transform_data, num_transforms)
        else: print(f"\tTransforms: None")

        print("\t--- PROPOSAL PARSE END ---")

        if last_substruc == 0: return 0
        else: return length

    def parse_isakmp_sa_payload_proposal_substruc(self, payload: bytes) -> str: # RFC 7296
        if payload == 0: return "NONE / No Next Payload (0)"
        else: return "More substructures available (2)"

    def parse_isakmp_sa_payload_proposal_protocol_id(self, payload: bytes) -> str: # RFC 7296
        if payload == 1: return "IKE (1)"
        elif payload == 2: return "AH (2)"
        elif payload == 2: return "ESP (3)"
        else: return f"{payload}"

    # Parse functions for ISAKMP - Security Association - Proposals - Transforms
    def parse_isakmp_sa_payload_proposal_transforms(self, data: bytes, num_of_transforms: int) -> None: # RFC 7296
        c = 1
        offset = 0
        while c <= num_of_transforms:
            print(f"\t\t--- TRANSFORM {c} PARSE BEGIN ---")

            last_substruc = data[0 + offset]
            reserved1 = "".join(str(bit) for bit in self.byte_to_bit_list(data[1 + offset]))
            length = int.from_bytes(data[2 + offset:4 + offset], "big")
            transform_type = data[4 + offset]
            reserved2 = "".join(str(bit) for bit in self.byte_to_bit_list(data[5 + offset]))
            transform_id = data[6 + offset:8 + offset]
            transform_attributes = data[8 + offset:length + offset]
            print(f"\t\tLast Proposal Substructre: {self.parse_isakmp_sa_payload_proposal_transform_substruc(last_substruc)}")
            print(f"\t\tReserved Bits: {reserved1}")
            print(f"\t\tLength: {length}")
            print(f"\t\tTransform Type: {self.parse_isakmp_sa_payload_proposal_transform_type(transform_type)}")
            print(f"\t\tReserved Bits: {reserved2}")
            print(f"\t\tTransform ID: {self.parse_isakmp_sa_payload_proposal_transform_id(transform_id, transform_type)}")
            if transform_attributes: print(f"\t\tTransform Attributes: {self.parse_isakmp_sa_payload_proposal_transform_attributes(transform_attributes)}")

            print(f"\t\t--- TRANSFORM {c} PARSE END ---")

            # Get current encryption algorithm
            if not self.IS_CURRENT_PACKET_INITIATOR: 
                if transform_type == 1: self.CURRENT_ENCRYPTION_ALGORITHM = int.from_bytes(transform_id, "big")

            offset += length
            c += 1

    def parse_isakmp_sa_payload_proposal_transform_id(self, payload: bytes, transform_type: int) -> str: # RFC 7296
        payload = int.from_bytes(payload, "big")

        encryption_algorithms = {
            0: "Reserved",
            1: "ENCR_DES_IV64",
            2: "ENCR_DES",
            3: "ENCR_3DES",
            4: "ENCR_RC5",
            5: "ENCR_IDEA",
            6: "ENCR_CAST",
            7: "ENCR_BLOWFISH",
            8: "ENCR_3IDEA",
            9: "ENCR_DES_IV32",
            10: "Reserved",
            11: "ENCR_NULL",
            12: "ENCR_AES_CBC",
            13: "ENCR_AES_CTR",
            14: "ENCR_AES_CCM_8",
            15: "ENCR_AES_CCM_12",
            16: "ENCR_AES_CCM_16",
            17: "Unassigned",
            18: "ENCR_AES_GCM_8",
            19: "ENCR_AES_GCM_12",
            20: "ENCR_AES_GCM_16",
            21: "ENCR_NULL_AUTH_AES_GMAC",
            22: "Reserved for IEEE P1619 XTS-AES",
            23: "ENCR_CAMELLIA_CBC",
            24: "ENCR_CAMELLIA_CTR",
            25: "ENCR_CAMELLIA_CCM_8",
            26: "ENCR_CAMELLIA_CCM_12",
            27: "ENCR_CAMELLIA_CCM_16",
            28: "ENCR_CHACHA20_POLY1305",
            29: "ENCR_AES_CCM_8_IIV",
            30: "ENCR_AES_GCM_16_IIV",
            31: "ENCR_CHACHA20_POLY1305_IIV",
            32: "ENCR_KUZNYECHIK_MGM_KTREE",
            33: "ENCR_MAGMA_MGM_KTREE",
            34: "ENCR_KUZNYECHIK_MGM_MAC_KTREE",
            35: "ENCR_MAGMA_MGM_MAC_KTREE",
        }

        prf_algorithms = {
            0: "Reserved",
            1: "PRF_HMAC_MD5",
            2: "PRF_HMAC_SHA1",
            3: "PRF_HMAC_TIGER",
            4: "PRF_AES128_XCBC",
            5: "PRF_HMAC_SHA2_256",
            6: "PRF_HMAC_SHA2_384",
            7: "PRF_HMAC_SHA2_512",
            8: "PRF_AES128_CMAC",
            9: "PRF_HMAC_STREEBOG_512",
        }

        integrity_algorithms = {
            0: "NONE",
            1: "AUTH_HMAC_MD5_96",
            2: "AUTH_HMAC_SHA1_96",
            3: "AUTH_DES_MAC",
            4: "AUTH_KPDK_MD5",
            5: "AUTH_AES_XCBC_96",
            6: "AUTH_HMAC_MD5_128",
            7: "AUTH_HMAC_SHA1_160",
            8: "AUTH_AES_CMAC_96",
            9: "AUTH_AES_128_GMAC",
            10: "AUTH_AES_192_GMAC",
            11: "AUTH_AES_256_GMAC",
            12: "AUTH_HMAC_SHA2_256_128",
            13: "AUTH_HMAC_SHA2_384_192",
            14: "AUTH_HMAC_SHA2_512_256",
        }

        dh_groups = {
            0: "NONE",
            1: "768-bit MODP Group",
            2: "1024-bit MODP Group",
            3: "Reserved",
            4: "Reserved",
            5: "1536-bit MODP Group",
            6: "Unassigned",
            7: "Unassigned",
            8: "Unassigned",
            9: "Unassigned",
            10: "Unassigned",
            11: "Unassigned",
            12: "Unassigned",
            13: "Unassigned",
            14: "2048-bit MODP Group",
            15: "3072-bit MODP Group",
            16: "4096-bit MODP Group",
            17: "6144-bit MODP Group",
            18: "8192-bit MODP Group",
            19: "256-bit random ECP group",
            20: "384-bit random ECP group",
            21: "521-bit random ECP group",
            22: "1024-bit MODP Group with 160-bit Prime Order Subgroup",
            23: "2048-bit MODP Group with 224-bit Prime Order Subgroup",
            24: "2048-bit MODP Group with 256-bit Prime Order Subgroup",
            25: "192-bit Random ECP Group",
            26: "224-bit Random ECP Group",
            27: "brainpoolP224r1",
            28: "brainpoolP256r1",
            29: "brainpoolP384r1",
            30: "brainpoolP512r1",
            31: "Curve25519",
            32: "Curve448",
            33: "GOST3410_2012_256",
            34: "GOST3410_2012_512",
        }

        sq_ids = {
            0: "No Extended Sequence Numbers",
            1: "Extended Sequence Numbers",
        }

        if transform_type == 1: # Encryption Algorithm Transform IDs
            if payload in encryption_algorithms:
                return f"{encryption_algorithms[payload]} ({payload})"
            else: return f"{payload}"
        elif transform_type == 2: # Pseudorandom Function Transform IDs
            if payload in prf_algorithms:
                return f"{prf_algorithms[payload]} ({payload})"
            else: return f"{payload}"
        elif transform_type == 3: # Integrity Algorithm Transform IDs
            if payload in integrity_algorithms:
                return f"{integrity_algorithms[payload]} ({payload})"
            else: return f"{payload}"
        elif transform_type == 4: # Key Exchange Method Transform IDs
            if payload in dh_groups:
                return f"{dh_groups[payload]} ({payload})"
            else: return f"{payload}"
        elif transform_type == 5: # Extended Sequence Numbers Transform IDs
            if payload in sq_ids:
                return f"{sq_ids[payload]} ({payload})"
            else: return f"{payload}"
        else: return f"{payload, transform_type}"      

    def parse_isakmp_sa_payload_proposal_transform_type(self, payload: bytes) -> str: # RFC 7296
        if payload == 1: return "Encryption Algorithm (ENCR) (1)"
        elif payload == 2: return "Pseudorandom Function (PRF) (2)"
        elif payload == 3: return "Integrity Algorithm (INTEG) (3)"
        elif payload == 4: return "Diffie-Hellman Group (D-H) (4)"
        elif payload == 5: return "Extended Sequence Numbers (ESN) (5)"
        elif payload == 6: return "Additional Key Exchange 1 (ADDKE1) (6)"
        elif payload == 7: return "Additional Key Exchange 2 (ADDKE2) (7)"
        elif payload == 8: return "Additional Key Exchange 3 (ADDKE3) (8)"
        elif payload == 9: return "Additional Key Exchange 4 (ADDKE4) (9)"
        elif payload == 10: return "Additional Key Exchange 5 (ADDKE5) (10)"
        elif payload == 11: return "Additional Key Exchange 6 (ADDKE6) (11)"
        elif payload == 12: return "Additional Key Exchange 7 (ADDKE7) (12)"
        else: return f"{payload}"

    def parse_isakmp_sa_payload_proposal_transform_substruc(self, payload: bytes) -> str: # RFC 7296
        if payload == 0: return "NONE / No Next Transform (0)"
        else: return "More transforms available (3)"

    # Parse functions for ISAKMP - Security Association - Proposals - Transforms - Attributes
    def parse_isakmp_sa_payload_proposal_transform_attributes(self, payload: bytes) -> None: # RFC 7296
        attribute_format = self.byte_to_bit_list(payload[0])[0]
        attribute_type = payload[1]
        if attribute_format == 0: 
            length = payload[2:4]
            attribute_value = payload[4:8]
        else: 
            length = "Not Transmitted"
            attribute_value = payload[2:4]

        print("\t\t\t--- TRANSFORM ATTRIBUTES PARSE BEGIN ---")

        if not attribute_format: print(f"\t\t\tFormat: Type/Length/Value (TLV)")
        else: print(f"\t\t\tFormat: Type/Value (TV)")
        if attribute_type == 14: print(f"\t\t\tType: Key Length (14)")
        else: print(f"\t\t\t{payload}")
        print(f"\t\t\tLength: {length}")
        print(f"\t\t\tValue: {attribute_value.hex()}")
        print(f"\t\t\tKey Length: {int.from_bytes(attribute_value, 'big')}")

        print("\t\t\t--- TRANSFORM ATTRIBUTES PARSE BEGIN ---")


    # Parse functions for ISAKMP - Key Exchange
    def parse_isakmp_kex_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Key Exchange (34) -----")

        if len(data) < 8: raise Exception("Invalid ISAKMP Key Exchange data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved1 = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        dh_group_num = data[4:6]
        reserved2 = "".join(str(bit) for bit in self.byte_to_bit_list(data[6])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[7]))
        kex_data = data[8:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved1}")
        print(f"Length: {length}")
        print(f"Diffie-Hellmann Group Number: {self.parse_isakmp_sa_payload_proposal_transform_id(dh_group_num, 4)}")
        print(f"Reserved Bits: {reserved2}")
        print(f"Key Exchange Data: {kex_data.hex()}")

        print("----- PAYLOAD PARSE END: Key Exchange (34) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)


    # Parse functions for ISAKMP - Identification I/R
    def parse_isakmp_identification_payload(self, data: bytes, type: int) -> None: # RFC 7296
        if not type: print("----- PAYLOAD PARSE BEGIN: Identification Initiator (35) -----")
        else: print("----- PAYLOAD PARSE BEGIN: Identification Responder (36) -----")

        if len(data) < 8: raise Exception("Invalid ISAKMP Identification data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved1 = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        id_type = data[4]
        reserved2 = "".join(str(bit) for bit in self.byte_to_bit_list(data[5])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[6])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[7]))
        id_data = data[8:length]


        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved1}")
        print(f"Length: {length}")
        print(f"ID Type: {self.parse_isakmp_identification_payload_type(id_type)}")
        print(f"Reserved Bits: {reserved2}")
        print(f"Identification Data: {self.parse_isakmp_identification_payload_value(id_data, int.from_bytes(id_type, 'big'))}")

        if not type: print("----- PAYLOAD PARSE END: Identification Initiator (35) -----")
        else: print("----- PAYLOAD PARSE END: Identification Responder (36) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)

    def parse_isakmp_identification_payload_type(self, payload: bytes) -> str: # RFC 7296
        if payload == 1: return "ID_IPV4_ADDR (1)"
        elif payload == 2: return "ID_FQDN (2)"
        elif payload == 3: return "ID_RFC822_ADDR (3)"
        elif payload == 5: return "ID_IPV6_ADDR (5)"
        elif payload == 9: return "ID_DER_ASN1_DN (9)"
        elif payload == 10: return "ID_DER_ASN1_GN (10)"
        elif payload == 11: return "ID_KEY_ID (11)"
        elif payload == 12: return "ID_FC_NAME (12)"
        elif payload == 13: return "ID_NULL (13)"
        else: return f"{payload}"

    def parse_isakmp_identification_payload_value(self, payload: bytes, type: int) -> str: # RFC 7296
        if type == 1: return f"{int.from_bytes(payload[0], 'big')}.{int.from_bytes(payload[1], 'big')}.{int.from_bytes(payload[2], 'big')}.{int.from_bytes(payload[3], 'big')}"
        elif type == 2: return f"{str(unhexlify(payload), 'ascii')}"
        elif type == 3: return f"{str(unhexlify(payload), 'ascii')}"
        elif type == 5: return f"{payload.hex()}"
        elif type == 9: return f"{payload.hex()}"
        elif type == 10: return  f"{payload.hex()}"
        elif type == 11: return  f"{payload.hex()}"
        elif type == 12: return  f"{payload.hex()}"
        elif type == 13: return  f"{payload.hex()}"
        else: return f"{payload.hex()}"


    # Parse functions for ISAKMP - Certificate
    def parse_isakmp_cert_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Certificate (37) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP Certificate data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved1 = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        cert_encoding = data[4]
        cert_data = data[5:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved1}")
        print(f"Length: {length}")
        print(f"Certificate Encoding: {self.parse_isakmp_cert_payload_encoding(cert_encoding)}")
        print(f"Certificate Data: {cert_data.hex()}")

        print("----- PAYLOAD PARSE END: Certificate (37) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)

    def parse_isakmp_cert_payload_encoding(self, payload: bytes) -> str: # RFC 7296
        if payload == 1: return "PKCS #7 wrapped X.509 certificate (1)"
        elif payload == 2: return "PGP Certificate (2)"
        elif payload == 3: return "DNS Signed Key (3)"
        elif payload == 4: return "X.509 Certificate - Signature (4)"
        elif payload == 6: return "Kerberos Token (6)"
        elif payload == 7: return "Certificate Revocation List (CRL) (7)"
        elif payload == 8: return "Authority Revocation List (ARL) (8)"
        elif payload == 9: return "SPKI Certificate (9)"
        elif payload == 10: return "X.509 Certificate - Attribute (10)"
        elif payload == 11: return "Raw RSA Key (11)"
        elif payload == 12: return "Hash and URL of X.509 certificate (12)"
        elif payload == 13: return "Hash and URL of X.509 bundle (13)"
        elif payload == 14: return "OCSP Content (14)"
        elif payload == 15: return "Raw Public Key (15)"
        else: return f"{payload}"


    # Parse functions for ISAKMP - Certificate Request
    def parse_isakmp_cert_request_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Certificate Request (38) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP Certificate Request data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved1 = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        cert_encoding = data[4]
        cert_data = data[5:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved1}")
        print(f"Length: {length}")
        print(f"Certificate Encoding: {self.parse_isakmp_cert_payload_encoding(cert_encoding)}")
        print(f"Certificate Authority: {cert_data.hex()}")

        print("----- PAYLOAD PARSE END: Certificate Request (38) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)


    # Parse functions for ISAKMP - Authentication
    def parse_isakmp_authentication_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Authentication (39) -----")

        if len(data) < 8: raise Exception("Invalid ISAKMP Authentication data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved1 = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        auth_method = data[4]
        reserved2 = "".join(str(bit) for bit in self.byte_to_bit_list(data[5])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[6])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[7]))
        auth_data = data[8:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved1}")
        print(f"Length: {length}")
        print(f"Authentication Method: {auth_method}")
        print(f"Reserved Bits: {reserved2}")
        print(f"Authentication Data: {auth_data.hex()}")

        print("----- PAYLOAD PARSE END: Authentication (39) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)

    def parse_isakmp_authentication_payload_method(self, payload: bytes) -> str: # RFC 7296
        auth_algorithms = {
            1: "RSA Digital Signature",
            2: "Shared Key Message Integrity Code",
            3: "DSS Digital Signature",
            4: "Unassigned",
            5: "Unassigned",
            6: "Unassigned",
            7: "Unassigned",
            8: "Unassigned",
            9: "ECDSA with SHA-256 on the P-256 curve",
            10: "ECDSA with SHA-384 on the P-384 curve",
            11: "ECDSA with SHA-512 on the P-521 curve",
            12: "Generic Secure Password Authentication Method",
            13: "NULL Authentication",
            14: "Digital Signature",
        }

        if payload in auth_algorithms:
            return f"{auth_algorithms[payload]} ({payload})"
        else: return f"{payload}"


    # Parse functions for ISAKMP - Nonce
    def parse_isakmp_nonce_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Nonce (40) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP Nonce data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        nonce_data = data[4:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved}")
        print(f"Length: {length}")
        print(f"Nonce Data: {nonce_data.hex()}")

        print("----- PAYLOAD PARSE END: Nonce (40) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)


    # Parse functions for ISAKMP - Notify
    def parse_isakmp_notify_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Notify (41) -----")

        if len(data) < 8: raise Exception("Invalid ISAKMP Notify data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        protocol_id = data[4]
        spi_size = data[5]
        notify_msg_type = int.from_bytes(data[6:8], "big")
        spi = data[8:spi_size]
        notification_data = data[8+spi_size:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved}")
        print(f"Length: {length}")
        print(f"Protocol ID: {self.parse_isakmp_sa_payload_proposal_protocol_id(protocol_id)}")
        print(f"SPI Size: {spi_size}")
        print(f"Notify Message Type: {self.parse_isakmp_notify_payload_type(notify_msg_type)}")
        if spi_size: print(f"SPI: {spi.hex()}")
        if not notification_data: print(f"Notofication Data: <MISSING>")
        else: print(f"Notofication Data: {notification_data.hex()}")

        print("----- PAYLOAD PARSE END: Notify (41) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)

    def parse_isakmp_notify_payload_type(self, payload: int) -> str: # RFC 7296
        messages = {
            1: "UNSUPPORTED_CRITICAL_PAYLOAD",
            4: "INVALID_IKE_SPI",
            5: "INVALID_MAJOR_VERSION",
            7: "INVALID_SYNTAX",
            9: "INVALID_MESSAGE_ID",
            11: "INVALID_SPI",
            14: "NO_PROPOSAL_CHOSEN",
            17: "INVALID_KE_PAYLOAD",
            24: "AUTHENTICATION_FAILED",
            34: "SINGLE_PAIR_REQUIRED",
            35: "NO_ADDITIONAL_SAS",
            36: "INTERNAL_ADDRESS_FAILURE",
            37: "FAILED_CP_REQUIRED",
            38: "TS_UNACCEPTABLE",
            39: "INVALID_SELECTORS",
            40: "UNACCEPTABLE_ADDRESSES",
            41: "UNEXPECTED_NAT_DETECTED",
            42: "USE_ASSIGNED_HoA",
            43: "TEMPORARY_FAILURE",
            44: "CHILD_SA_NOT_FOUND",
            45: "INVALID_GROUP_ID",
            46: "AUTHORIZATION_FAILED",
            47: "STATE_NOT_FOUND",
            48: "TS_MAX_QUEUE",
            16384: "INITIAL_CONTACT",
            16385: "SET_WINDOW_SIZE",
            16386: "ADDITIONAL_TS_POSSIBLE",
            16387: "IPCOMP_SUPPORTED",
            16388: "NAT_DETECTION_SOURCE_IP",
            16389: "NAT_DETECTION_DESTINATION_IP",
            16390: "COOKIE",
            16391: "USE_TRANSPORT_MODE",
            16392: "HTTP_CERT_LOOKUP_SUPPORTED",
            16393: "REKEY_SA",
            16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
            16395: "NON_FIRST_FRAGMENTS_ALSO",
            16396: "MOBIKE_SUPPORTED",
            16397: "ADDITIONAL_IP4_ADDRESS",
            16398: "ADDITIONAL_IP6_ADDRESS",
            16399: "NO_ADDITIONAL_ADDRESSES",
            16400: "UPDATE_SA_ADDRESSES",
            16401: "COOKIE2",
            16402: "NO_NATS_ALLOWED",
            16403: "AUTH_LIFETIME",
            16404: "MULTIPLE_AUTH_SUPPORTED",
            16405: "ANOTHER_AUTH_FOLLOWS",
            16406: "REDIRECT_SUPPORTED",
            16407: "REDIRECT",
            16408: "REDIRECTED_FROM",
            16409: "TICKET_LT_OPAQUE",
            16410: "TICKET_REQUEST",
            16411: "TICKET_ACK",
            16412: "TICKET_NACK",
            16413: "TICKET_OPAQUE",
            16414: "LINK_ID",
            16415: "USE_WESP_MODE",
            16416: "ROHC_SUPPORTED",
            16417: "EAP_ONLY_AUTHENTICATION",
            16418: "CHILDLESS_IKEV2_SUPPORTED",
            16419: "QUICK_CRASH_DETECTION",
            16420: "IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
            16421: "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED",
            16422: "IKEV2_MESSAGE_ID_SYNC",
            16423: "IPSEC_REPLAY_COUNTER_SYNC",
            16424: "SECURE_PASSWORD_METHODS",
            16425: "PSK_PERSIST",
            16426: "PSK_CONFIRM",
            16427: "ERX_SUPPORTED",
            16428: "IFOM_CAPABILITY",
            16429: "SENDER_REQUEST_ID",
            16430: "IKEV2_FRAGMENTATION_SUPPORTED",
            16431: "SIGNATURE_HASH_ALGORITHMS",
            16432: "CLONE_IKE_SA_SUPPORTED",
            16433: "CLONE_IKE_SA",
            16434: "PUZZLE",
            16435: "USE_PPK",
            16436: "PPK_IDENTITY",
            16437: "NO_PPK_AUTH",
            16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
            16439: "IP4_ALLOWED",
            16440: "IP6_ALLOWED",
            16441: "ADDITIONAL_KEY_EXCHANGE",
            16442: "USE_AGGFRAG",
            16443: "SUPPORTED_AUTH_METHODS",
            16444: "SA_RESOURCE_INFO"
        }

        if payload in messages: return f"{messages[payload]} ({payload})"
        else: return f"{payload}"


    # Parse functions for ISAKMP - Delete
    def parse_isakmp_delete_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Delete (42) -----")

        if len(data) < 8: raise Exception("Invalid ISAKMP Delete data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        protocol_id = data[4]
        spi_size = data[5]
        num_spi = int.from_bytes(data[6:8], "big")
        spi_data = data[8:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved}")
        print(f"Length: {length}")
        print(f"Protocol ID: {self.parse_isakmp_sa_payload_proposal_protocol_id(protocol_id)}")
        print(f"SPI Size: {spi_size}")
        print(f"Number of SPIs: {num_spi}")
        print(f"SPIs: {spi_data.hex()}")

        print("----- PAYLOAD PARSE END: Delete (42) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)


    # Parse functions for ISAKMP - Vendor ID
    def parse_isakmp_vid_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Vendor ID (VID) (43) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP Vendor ID data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        vid_data = data[4:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved}")
        print(f"Length: {length}")
        print(f"Vendor ID: {vid_data.hex()}")

        print("----- PAYLOAD PARSE END: Vendor ID (VID) (43) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)


    # Parse functions for ISAKMP - Traffic Selector I/R
    def parse_isakmp_ts_payload(self, data: bytes, ts_type: int) -> None: # RFC 7296
        if not ts_type: print("----- PAYLOAD PARSE BEGIN: Traffic Selector Initiator (44) -----")
        else: print("----- PAYLOAD PARSE BEGIN: Traffic Selector Responder (45) -----")

        if len(data) < 8: raise Exception("Invalid ISAKMP Traffic Selector data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved1 = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        num_ts = data[4]
        reserved2 = "".join(str(bit) for bit in self.byte_to_bit_list(data[5])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[6])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[7]))
        ts_data = data[8:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved1}")
        print(f"Length: {length}")
        print(f"Number of TSs: {num_ts}")
        print(f"Reserved Bits: {reserved2}")
        self.parse_isakmp_ts_payload_ts(ts_data, num_ts)

        if not ts_type: print("----- PAYLOAD PARSE END: Traffic Selector Initiator (44) -----")
        else: print("----- PAYLOAD PARSE END: Traffic Selector Responder (45) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)

    # Parse functions for ISAKMP - Traffic Selector I/R - Traffic Selector
    def parse_isakmp_ts_payload_ts(self, data: bytes, ts_count: int) -> None: # RFC 7296
        c = 0
        offset = 0
        while c < ts_count:
            print(f"----- TRAFFIC SELECTOR PARSE BEGIN: Traffic Selector {c + 1} -----")

            if len(data) < 8: raise Exception("Invalid ISAKMP Trafrfic Selector data")
            ts_type = data[0 + offset]
            ipid = data[1 + offset]
            length = int.from_bytes(data[2 + offset:4 + offset], "big")
            sport = int.from_bytes(data[4 + offset:6 + offset], "big")
            dport = int.from_bytes(data[6 + offset:8 + offset], "big")
            if ts_type == 7:
                saddr = data[8 + offset:12 + offset]
                saddr_parsed = f"{int.from_bytes(data[8 + offset], 'big')}.{int.from_bytes(data[9 + offset], 'big')}.{int.from_bytes(data[10 + offset], 'big')}.{int.from_bytes(data[11 + offset], 'big')}"
                eaddr = data[12 + offset:16 + offset]
                eaddr_parsed = f"{int.from_bytes(data[12 + offset], 'big')}.{int.from_bytes(data[13 + offset], 'big')}.{int.from_bytes(data[14 + offset], 'big')}.{int.from_bytes(data[15 + offset], 'big')}"
            else:
                saddr = data[8 + offset:24 + offset]
                saddr_parsed = saddr
                eaddr = data[24 + offset:40 + offset]
                eaddr_parsed = eaddr

            print(f"Traffic Selector Type: {self.parse_isakmp_ts_payload_ts_type(ts_type)}")
            print(f"IP protocol ID: {ipid}")
            print(f"Selector length: {length}")
            print(f"Start Port: {sport}")
            print(f"End Port: {dport}")
            print(f"Starting Address: {saddr_parsed}")
            print(f"Ending Address: {eaddr_parsed}")
            

            print(f"----- TRAFFIC SELECTOR PARSE END: Traffic Selector {c + 1} -----")

            c += 1
            offset += length

    def parse_isakmp_ts_payload_ts_type(self, payload: bytes) -> str: # RFC 7296
        if payload == 7: return "TS_IPV4_ADDR_RANGE (7)"
        elif payload == 8: return "TS_IPV6_ADDR_RANGE (8)"
        elif payload == 9: return "TS_FC_ADDR_RANGE (9)"
        elif payload == 10: return "TS_SECLABEL (10)"
        else: return f"{payload}"


    # Parse functions for ISAKMP - Encrypted Payload
    def parse_isakmp_encrypted_authenticated_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Encrypted and Authenticated Payload (46) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP Encrypted Payload data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        
        iv_length = self.map_enc_to_iv(self.CURRENT_ENCRYPTION_ALGORITHM)

        iv = data[4:iv_length]
        encrypted_data = data[iv_length:]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved}")
        print(f"Length: {length}")
        print(f"Initialization Vector: {iv.hex()}")
        print(f"Encrypted Data: {encrypted_data.hex()}")

        print("----- PAYLOAD PARSE END: Encrypted and Authenticated Payload (46) -----")


    # Parse functions for ISAKMP - Configuration
    def parse_isakmp_configuration_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: Configuration (47) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP Configuration data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved1 = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        cfg_type = data[4]
        reserved2 = "".join(str(bit) for bit in self.byte_to_bit_list(data[5])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[6])) + "".join(str(bit) for bit in self.byte_to_bit_list(data[7]))
        config_attributes = data[8: length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved1}")
        print(f"Length: {length}")
        print(f"Configuration Type: {self.parse_isakmp_configuration_payload_type(cfg_type)}")
        print(f"Reserved Bits: {reserved2}")
        self.parse_isakmp_configuration_payload_attributes(config_attributes, length)

        print("----- PAYLOAD PARSE END: Configuration (47) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)

    # Parse functions for ISAKMP - Configuration - Type
    def parse_isakmp_configuration_payload_type(self, payload: bytes) -> str: # RFC 7296
        if payload == 1: return f"CFG_REQUEST (1)"
        elif payload == 2: return f"CFG_REPLY (2)"
        elif payload == 3: return f"CFG_SET (3)"
        elif payload == 4: return f"CFG_ACK (4)"
        else: return f"{payload}"

    # Parse functions for ISAKMP - Configuration - Attributes
    def parse_isakmp_configuration_payload_attributes(self, data: bytes, payload_length: int) -> None: # RFC 7296
        c = 1
        offset = 0
        while offset <= payload_length - 8: # - config header size
            print(f"\t--- CONFIGURATION ATTRIBUTE {c} PARSE BEGIN ---")

            reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[0 + offset]))[:1]
            attribute_type = int("".join(str(bit) for bit in self.byte_to_bit_list(data[0 + offset]))[1:], 2)
            length = int.from_bytes(data[2 + offset:4 + offset], "big")
            value = data[4 + offset]

            print(f"\tReserved Bit: {reserved}")
            print(f"\tAttribute Type: {self.parse_isakmp_configuration_payload_attribute_type(attribute_type)}")
            print(f"\tLength: {length}")
            print(f"\tValue: {value.hex()}")

            print(f"\t--- CONFIGURATION ATTRIBUTE {c} PARSE END ---")

            offset += (length + 4)
            c += 1

    # Parse functions for ISAKMP - Configuration - Attribute - Type
    def parse_isakmp_configuration_payload_attribute_type(self, payload: bytes) -> str: # RFC 7296
        attribute_types = {
            1: "INTERNAL_IP4_ADDRESS",
            2: "INTERNAL_IP4_NETMASK",
            3: "INTERNAL_IP4_DNS",
            4: "INTERNAL_IP4_NBNS",
            6: "INTERNAL_IP4_DHCP",
            7: "APPLICATION_VERSION",
            8: "INTERNAL_IP6_ADDRESS",
            10: "INTERNAL_IP6_DNS",
            12: "INTERNAL_IP6_DHCP",
            13: "INTERNAL_IP4_SUBNET",
            14: "SUPPORTED_ATTRIBUTES",
            15: "INTERNAL_IP6_SUBNET",
            16: "MIP6_HOME_PREFIX",
            17: "INTERNAL_IP6_LINK",
            18: "INTERNAL_IP6_PREFIX",
            19: "HOME_AGENT_ADDRESS",
            20: "P_CSCF_IP4_ADDRESS",
            21: "P_CSCF_IP6_ADDRESS",
            22: "FTT_KAT",
            23: "EXTERNAL_SOURCE_IP4_NAT_INFO",
            24: "TIMEOUT_PERIOD_FOR_LIVENESS_CHECK",
            25: "INTERNAL_DNS_DOMAIN",
            26: "INTERNAL_DNSSEC_TA",
            27: "ENCDNS_IP4",
            28: "ENCDNS_IP6",
            29: "ENCDNS_DIGEST_INFO",
        }

        if payload in attribute_types:
            return f"{attribute_types[payload]} ({payload})"
        else: return f"{payload}"


    # Parse functions for ISAKMP - EAP
    def parse_isakmp_eap_payload(self, data: bytes) -> None: # RFC 7296
        print("----- PAYLOAD PARSE BEGIN: EAP Payload (48) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP EAP data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        eap_code = data[4]
        eap_id = "".join(str(bit) for bit in self.byte_to_bit_list(data[5]))
        eap_length = int.from_bytes(data[6:8], "big")
        if eap_code == 1 or eap_code == 2: 
            eap_type = "".join(str(bit) for bit in self.byte_to_bit_list(data[8]))
            eap_data = data[9:length]
        else:
            eap_type = 0
            eap_data = data[8:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved}")
        print(f"Length: {length}")
        print(f"EAP Message Code: {self.parse_isakmp_eap_payload_code(eap_code)}")
        print(f"EAP Message Identifier: {eap_id}")
        print(f"EAP Message Length: {eap_length}")
        print(f"EAP Message Type: {eap_type}")
        print(f"EAP Message Data: {eap_data.hex()}")

        print("----- PAYLOAD PARSE END: EAP Payload (48) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)

    # Parse functions for ISAKMP - EAP - Type
    def parse_isakmp_eap_payload_code(self, payload: bytes) -> str: # RFC 7296
        if payload == 1: return "Request (1)"
        elif payload == 2: return "Response (2)"
        elif payload == 2: return "Success (3)"
        elif payload == 2: return "Failure (4)"
        else: return f"{payload}"


    # Parse functions for ISAKMP - GSPM
    def parse_isakmp_GSPM_payload(self, data: bytes) -> None: # RFC 6467 #TODO:SUBTYPE
        print("----- PAYLOAD PARSE BEGIN: Generic Secure Password Method Payload (49) -----")

        if len(data) < 4: raise Exception("Invalid ISAKMP EAP data")
        next_payload = data[0]
        critical = self.byte_to_bit_list(data[1])[0]
        reserved = "".join(str(bit) for bit in self.byte_to_bit_list(data[1]))[1:]
        length = int.from_bytes(data[2:4], "big")
        gspm_data = data[4:length]

        print(f"Next Payload: {self.parse_isakmp_next_payload(next_payload)}")
        print(f"Critical Bit: {self.parse_isakmp_critical_bit(critical)}")
        print(f"Reserved Bits: {reserved}")
        print(f"Length: {length}")
        print(f"GSPM Data: {gspm_data.hex()}")

        print("----- PAYLOAD PARSE END: Generic Secure Password Method Payload (49) -----")

        data = data[length:]
        if next_payload: self.parse_isakmp_payloads(data, next_payload)


    # Helper functions
    def map_enc_to_iv(self, encryption_algorithm_id: int) -> int: # https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
        encryption_algorithms_iv_lengths = {
            0: None,              # Reserved
            1: 8,                 # ENCR_DES_IV64
            2: 8,                 # ENCR_DES
            3: 8,                 # ENCR_3DES
            4: 8,                 # ENCR_RC5 (variable, meist 8)
            5: 8,                 # ENCR_IDEA
            6: 8,                 # ENCR_CAST
            7: 8,                 # ENCR_BLOWFISH
            8: 8,                 # ENCR_3IDEA
            9: 4,                 # ENCR_DES_IV32
            10: None,             # Reserved
            11: 0,                # ENCR_NULL
            12: 16,               # ENCR_AES_CBC
            13: 16,               # ENCR_AES_CTR
            14: 999,              # ENCR_AES_CCM_8 (7 bis 13)
            15: 999,              # ENCR_AES_CCM_12 (7 bis 13)
            16: 999,              # ENCR_AES_CCM_16 (7 bis 13)
            17: None,             # Unassigned
            18: 8,                # ENCR_AES_GCM_8
            19: 8,                # ENCR_AES_GCM_12
            20: 8,                # ENCR_AES_GCM_16
            21: 12,               # ENCR_NULL_AUTH_AES_GMAC
            22: None,             # Reserved for IEEE P1619 XTS-AES
            23: 16,               # ENCR_CAMELLIA_CBC
            24: 16,               # ENCR_CAMELLIA_CTR
            25: 999,              # ENCR_CAMELLIA_CCM_8 (7 bis 13)
            26: 999,              # ENCR_CAMELLIA_CCM_12 (7 bis 13)
            27: 999,              # ENCR_CAMELLIA_CCM_16 (7 bis 13)
            28: 12,               # ENCR_CHACHA20_POLY1305
            29: 999,              # ENCR_AES_CCM_8_IIV (7 bis 13)
            30: 8,                # ENCR_AES_GCM_16_IIV
            31: 12,               # ENCR_CHACHA20_POLY1305_IIV
            32: 16,               # ENCR_KUZNYECHIK_MGM_KTREE
            33: 8,                # ENCR_MAGMA_MGM_KTREE
            34: 16,               # ENCR_KUZNYECHIK_MGM_MAC_KTREE
            35: 8,                # ENCR_MAGMA_MGM_MAC_KTREE
        }

        if encryption_algorithm_id in encryption_algorithms_iv_lengths:
            return encryption_algorithms_iv_lengths[encryption_algorithm_id]
        else: return 999
    
    def byte_to_bit_list(self, byte_obj: bytes) -> list:
        # Stelle sicher, dass byte_obj ein Byte-Objekt oder eine Bytes-Sequenz ist
        if isinstance(byte_obj, int):
            byte_obj = bytes([byte_obj])
        elif not isinstance(byte_obj, bytes):
            raise TypeError("Input must be an int or bytes object")

        # Konvertiere das Byte-Objekt in eine Binärdarstellung und extrahiere Einzelbits
        bit_list = []
        for byte in byte_obj:
            bits = f"{byte:08b}"  # Konvertiert das Byte in eine 8-Bit-Binärdarstellung
            bit_list.extend(bits)  # Fügt alle 8 Bits zur Liste hinzu
        for i in range(len(bit_list)):
            bit_list[i] = int(bit_list[i])
        return bit_list

    def split_byte_into_4bit_parts(self, byte_obj: bytes) -> list:
        # Stelle sicher, dass byte_obj ein Byte-Objekt oder eine Bytes-Sequenz ist
        if isinstance(byte_obj, int):
            byte_obj = bytes([byte_obj])
        elif isinstance(byte_obj, bytes):
            pass
        else:
            raise TypeError("Input must be an int or bytes object")

        # Konvertiere das Byte-Objekt in eine Binärdarstellung
        binary_string = "".join(f'{byte:08b}' for byte in byte_obj)
        
        # Liste für die 4-Bit-Teile
        parts = []
        
        # Teile die Binärdarstellung in 4-Bit-Teile
        for i in range(0, len(binary_string), 4):
            four_bit_part = binary_string[i:i+4]
            parts.append(four_bit_part)
        
        return [int(part, 2) for part in parts]
    
"""---------- ISAKMP SECTION END ----------"""

