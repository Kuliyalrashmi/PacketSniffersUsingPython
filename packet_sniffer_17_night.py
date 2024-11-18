from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPResponse
from time import time
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.layers.http import HTTP, HTTPResponse
import csv
import logging
import psutil
import socket

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
TIME_WINDOW = timedelta(minutes=1)

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.session_data = defaultdict(lambda: {
            "spkts": 0,
            "sbytes": 0,
            "sttl": 0,
            "swin": 0,
            "stcpb": 0,
            "smean": 0,
            "dpkts": 0,
            "dbytes": 0,
            "dttl": 0,
            "dwin": 0,
            "dtcpb": 0,
            "dmean": 0,
            "ct_srv_src": 0,
            "tcprtt": 0,
            "syn_timestamp": 0,
            "synack_timestamp": 0,
            "ack_timestamp": 0,
            "data_timestamp": 0,
            "trans_depth": 0,
            "response_body_len": 0,
            "timestamps_dst": [],
            "first_timestamp": 0,
            "last_timestamp": 0,
        })
        self.packet_attributes = {}
        self.packet_history = defaultdict(list)
        self.packet_history_time_window = timedelta(seconds=60)

        self.state_ttl_counter = defaultdict(int) 
        self.dst_ltm_counter = defaultdict(list)  
        self.src_dport_ltm_counter = defaultdict(list)  
        self.dst_sport_ltm_counter = defaultdict(list)  
        self.dst_src_ltm_counter = defaultdict(list)

        self.ftp_login_counter = defaultdict(bool)  
        self.ftp_cmd_counter = defaultdict(int)  
        self.http_method_counter = defaultdict(int)

        self.src_ltm_counter = defaultdict(int)    
        self.srv_dst_counter = defaultdict(set)   
        self.ips_ports_counter = defaultdict(set) 
        self.attack_category = defaultdict(str)

        self.label = defaultdict(str)

        self.ftp_commands = {"USER", "PASS", "QUIT", "RETR", "STOR", "DELE", "LIST"}
        self.http_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}

        self.port_to_service = {
            21: "FTP",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            161: "SNMP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
        }

    def determine_state(self,packet):
        """Determines the connection state based on TCP flags."""
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            if tcp_flags & 0x01:  # FIN
                return "FIN"
            elif tcp_flags & 0x04:  # RST
                return "RST"
            elif tcp_flags & 0x02:  # SYN
                return "SYN"
            elif tcp_flags & 0x10:  # ACK
                return "ACK"
        return "UNKNOWN"

    def GetBasicFeatures(self, packet):
        """Extracts basic features from a packet."""
        session_key = (packet[IP].src, packet[IP].dst, packet.sport, packet.dport)
        if IP in packet:
            self.packet_attributes = {
                "proto": packet[IP].proto,
                "service": self.port_to_service.get(packet.dport, "Unknown") if TCP in packet or UDP in packet else "Unknown",
                "state": self.determine_state(packet),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
                "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
                "protocol": "TCP" if TCP in packet else ("UDP" if UDP in packet else "Other"),
                "timestamp": time(),
                "packet_size": len(packet),
                "ttl": packet[IP].ttl
            }

            if session_key not in self.session_data:
                self.initialize_session(session_key)

            self.session_data[session_key]["last_timestamp"] = self.packet_attributes["timestamp"]
        return session_key

    def initialize_session(self, session_key):
        self.session_data[session_key] = {
                "spkts": 0,
                "sbytes": 0,
                "sttl": 0,
                "swin": 0,
                "stcpb": 0,
                "smean": 0,
                "dpkts": 0,
                "dbytes": 0,
                "dttl": 0,
                "dwin": 0,
                "dtcpb": 0,
                "dmean": 0,
                "ct_srv_src": 0,
                "tcprtt": 0,
                "syn_timestamp": 0,
                "synack_timestamp": 0,
                "ack_timestamp": 0,
                "data_timestamp": 0,
                "trans_depth": 0,
                "response_body_len": 0,
                "timestamps_dst": [],
                "first_timestamp": self.packet_attributes.get("timestamp", 0),
                "last_timestamp": self.packet_attributes.get("timestamp", 0),
        }

    def track_packet_history(self, session_key, packet):
        current_time = time()
        session_history = self.packet_history[session_key]

        session_history.append(self.packet_attributes.copy())

        self.packet_history[session_key] = [
            p for p in session_history if current_time - p["timestamp"] <= self.packet_history_time_window.total_seconds()
        ]

    def GetPacketRelatedFeatures(self, session_key, packet):
        if session_key not in self.session_data:
            self.initialize_session(session_key)
        session = self.session_data[session_key]

        session["last_timestamp"] = self.packet_attributes["timestamp"]


        self.state_ttl_counter[(self.packet_attributes["state"], self.packet_attributes["ttl"])] += 1
        self.dst_ltm_counter[self.packet_attributes["dst_ip"]].append(self.packet_attributes["timestamp"])
        self.src_dport_ltm_counter[(self.packet_attributes["src_ip"], self.packet_attributes["dst_port"])].append(self.packet_attributes["timestamp"])
        self.dst_sport_ltm_counter[(self.packet_attributes["dst_ip"], self.packet_attributes["src_port"])].append(self.packet_attributes["timestamp"])
        self.dst_src_ltm_counter[(self.packet_attributes["src_ip"], self.packet_attributes["dst_ip"])].append(self.packet_attributes["timestamp"])

        if packet[IP].src == self.packet_attributes["src_ip"]:
            session["spkts"] += 1
            session["sbytes"] += self.packet_attributes["packet_size"]
            session["sttl"] = self.packet_attributes["ttl"]

            if packet.haslayer(TCP):
                session["swin"] = packet[TCP].window
                session["stcpb"] += max(len(packet[TCP].payload), 0)
            else:
                session["swin"] = session.get("swin", 0)

            session["smean"] = session["sbytes"] / max(session["spkts"], 1)

        if packet[IP].dst == self.packet_attributes["dst_ip"]:
            session["dpkts"] += 1
            session["dbytes"] += self.packet_attributes["packet_size"]
            session["dttl"] = self.packet_attributes["ttl"]

            if packet.haslayer(TCP):  
                session["dwin"] = packet[TCP].window
                session["dtcpb"] += max(len(packet[TCP].payload), 0)
            else:
                session["dwin"] = session.get("dwin", 0)

            session["dmean"] = session["dbytes"] / max(session["dpkts"], 1)
            session["timestamps_dst"].append(self.packet_attributes["timestamp"])

        if packet.haslayer(TCP):
            session["tcprtt"] = session.get("tcprtt", 0)
            session["synack"] = session.get("synack", 0)
            session["ackdat"] = session.get("ackdat", 0)

            if "syn_timestamp" in session and "synack_timestamp" in session:
                session["tcprtt"] = session["synack_timestamp"] - session["syn_timestamp"]

            if "syn_timestamp" in session and "synack_timestamp" not in session:
                if packet[TCP].flags == "SA":  # SYN-ACK
                    session["synack_timestamp"] = self.packet_attributes["timestamp"]
                    session["synack"] = session["synack_timestamp"] - session["syn_timestamp"]

            if "data_timestamp" in session and "ack_timestamp" not in session:
                if packet[TCP].flags == "A":  # ACK
                    session["ack_timestamp"] = self.packet_attributes["timestamp"]
                    session["ackdat"] = session["ack_timestamp"] - session["data_timestamp"]

        trans_depth = 0
        content_length = 0
        if packet.haslayer(HTTP):
            if packet[HTTP].Method in ["GET", "POST"]:
                session["trans_depth"] += 1
                trans_depth += session["trans_depth"]
        if packet.haslayer(HTTPResponse):
            if "Content-Length" in packet[HTTPResponse].headers:
                content_len = int(packet[HTTPResponse].headers["Content-Length"])
                session["response_body_len"] = content_len
            elif packet.haslayer(TCP) and packet[TCP].payload:
                session["response_body_len"] = len(packet[TCP].payload)

        session["ct_srv_src"] += 1
        session["smean"] = session["sbytes"] / max(session["spkts"], 1)
        session["dmean"] = session["dbytes"] / max(session["dpkts"], 1)

        self.packet_attributes.update({
            "dur": session["last_timestamp"] - session["first_timestamp"],
            "spkts": session["spkts"],
            "sbytes": session["sbytes"],
            "sttl": session["sttl"],
            "swin": session.get("swin", 0),
            "stcpb": session.get("stcpb", 0),
            "smean": session["smean"],
            "dpkts": session["dpkts"],
            "dbytes": session["dbytes"],
            "dttl": session["dttl"],
            "dwin": session.get("dwin", 0),
            "dtcpb": session.get("dtcpb", 0),
            "dmean": session["dmean"],
            "ct_srv_src": session["ct_srv_src"],
            "response_body_len": session.get("response_body_len", 0),
            "tcprtt": session.get("tcprtt", 0),
            "trans_depth"  : session.get("trans_depth" , 0),
            "tcprtt": session.get("tcprtt", 0),  
            "synack": session.get("synack", 0),  
            "ackdat": session.get("ackdat", 0),
        })

        self.track_packet_history(session_key, packet)

    def update_session_data(self, session_key, features , packet):
        if session_key not in self.session_data:
            self.session_data[session_key].update({
                "first_timestamp": features["timestamp"],
                "last_timestamp": features["timestamp"]
            })

        session = self.session_data[session_key]
        session["last_timestamp"] = features["timestamp"]
        session["spkts"] += 1
        session["sbytes"] += features["packet_size"]
        session["sttl"] = features["ttl"]
        session["smean"] = session["sbytes"] / max(session["spkts"], 1)

        if packet.haslayer(TCP):
            session["swin"] = packet[TCP].window
            session["stcpb"] += max(len(packet[TCP].payload), 0)

        self.packet_history[session_key].append(features)
        self.packet_history[session_key] = [
            p for p in self.packet_history[session_key]
            if features["timestamp"] - p["timestamp"] <= self.packet_history_time_window.total_seconds()
        ]


    def CalculateTimeMetrics(self, packet, session_key):
        """
        Calculate metrics: ct_src_ltm, ct_srv_dst, is_sm_ips_ports, attack_cat, label based on packet data.
        This function now handles previous packets for a given session.
        """

        session = self.session_data[session_key]
        history = self.packet_history[session_key]
        current_time = time()

        for pkt in history:
            src_ip, dst_ip = pkt["src_ip"], pkt["dst_ip"]
            src_port, dst_port = pkt["src_port"], pkt["dst_port"]
            self.src_ltm_counter[src_ip] += 1
            self.srv_dst_counter[src_ip].add(dst_port)
            self.ips_ports_counter[(src_ip, src_port)].add(dst_ip)

        for ip in self.src_ltm_counter:
            session["ct_src_ltm"] = self.src_ltm_counter[ip]
            session["ct_srv_dst"] = len(self.srv_dst_counter[ip])
            session["is_sm_ips_ports"] = "Yes" if len(self.ips_ports_counter.get((ip, 80), [])) < 5 else "No"
            session["attack_cat"] = self.attack_category[ip]
            session["label"] = self.label.get(ip, "Normal")

        self.packet_attributes.update({
            "ct_src_ltm" : session["ct_src_ltm"],
            "ct_srv_dst" : session["ct_srv_dst"],
            "is_sm_ips_ports" : session["is_sm_ips_ports"],
            "attack_cat" : session["attack_cat"],
            "label"  : session["label"],
        })


    def CalculateFttpMetrics(self,packet, session_key):
        """
        Calculate FTP metrics: is_ftp_login and ct_ftp_cmd based on packet data.
        """
        session = self.session_data[session_key]
        history = self.packet_history[session_key]
        
        for pkt in history:
            if pkt['protocol'] == 'FTP':
                ftp_cmd = pkt.get('ftp_cmd', '')
                if ftp_cmd in self.ftp_commands:  
                    ftp_cmd_counter[ftp_cmd] += 1  
                    if ftp_cmd == 'USER' or ftp_cmd == 'PASS':  
                        ftp_login_counter[pkt['src_ip']] = True  

        for ip, logged_in in ftp_login_counter.items():
            print(f"FTP login status for {ip}: {'Login Successful' if logged_in else 'Login Not Attempted'}")
            
            history[ip] = {'is_ftp_login': 1 if logged_in else 0}
        
        total_count = 0
        for cmd, count in ftp_cmd_counter.items():
            print(f"FTP command '{cmd}' count: {count}")
            total_count += count
        
        self.packet_attributes.update({
            'ct_ftp_cmd' : total_count 
        })


    def CalculateHttpMetrics(self,packet):
        """
        Calculate HTTP metrics: ct_flw_http_mthd based on packet data.
        """
        session = self.session_data[session_key]
        history = self.packet_history[session_key]
        
        for packet in history:
            if packet['protocol'] == 'HTTP':
                http_method = packet['http_method']  
                if http_method in http_methods:
                    http_method_counter[http_method] += 1  
        for method, count in http_method_counter.items():
            packet_data['ct_flw_http_mthd'] += count
        
        self.packet_attributes.update({
            "ct_flw_http_mthd" : packet_data['ct_flw_http_mthd']
        })

    def process_packet(self,packet):
        try:
            if IP not in packet:
                logging.warning("Packet does not contain an IP layer.")
                return

            self.packet_count += 1

            self.packet_attributes.update({
                # "packet_id" : self.packet_count,
                "timestamp": time(),
                "packet_size" : len(packet)
            })
                
            session_key = self.GetBasicFeatures(packet)
                
            self.GetPacketRelatedFeatures(session_key,packet)
            self.update_session_data(session_key, self.packet_attributes, packet)
            self.CalculateTimeMetrics(packet , session_key )
                

            if TCP in packet:
                self.packet_attributes.update({
                    "state" : self.determine_state(packet)
                })
            else:
                self.packet_attributes({
                    "state" : "UNKNOWN"
                })

            src_port = self.packet_attributes.get("src_port")
            dst_port = self.packet_attributes.get("dst_port")

            if src_port == 21 or dst_port == 21:
                self.CalculateFttpMetrics(packet , session_key)
            if src_port == 80 or dst_port == 80 or self.packet_attributes.get("service") == "HTTP":
                self.CalculateHttpMetrics(packet ,session_key)

            print(self.packet_attributes)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    @staticmethod
    def Get_Interface():
        print("Checking for Network Interfaces...")

        interfaces = psutil.net_if_addrs()
        print("Available Network Interfaces:", list(interfaces.keys()))

        for index, (iface_name, iface_addresses) in enumerate(interfaces.items(), start=1):
            print(f"\nInterface {index}: {iface_name}")
            for addr in iface_addresses:
                print("Address:", addr.address)

        try:
            user_device_option = int(input("\nChoose an option by index: ")) - 1
            selected_iface = list(interfaces.keys())[user_device_option]
            print(f"You selected: {selected_iface}")
            return selected_iface
        except (ValueError, IndexError):
            print("Invalid option chosen.")
            return "invalid"

    def is_valid_interface(self,iface_name):
        iface_stats = psutil.net_if_stats().get(iface_name)
        iface_addrs = psutil.net_if_addrs().get(iface_name, [])

        if iface_stats and iface_stats.isup:
            if any(addr.address for addr in iface_addrs if addr.family == socket.AF_INET):
                return True
        return False

    def sniffer(self):
        selected_iface = self.Get_Interface()
        if selected_iface != "invalid" and self.is_valid_interface(selected_iface):
            print(f"Interface '{selected_iface}' is valid for packet sniffing.")
        else:
            print(f"Interface '{selected_iface}' is not valid for packet sniffing. Sniffing on default interface.\n")
            selected_iface = None

        if selected_iface:
            print(f"Sniffing packets from {selected_iface} :")
            sniff(iface=selected_iface, prn= lambda pkt : self.process_packet(pkt), store=0, count=10 , filter = "ip")
        else:
            print("Sniffing packets from default interface:")
            sniff(prn=lambda pkt : self.process_packet(pkt), store=0, count=10 , filter = "ip")
        
        
if __name__ == "__main__":
    pack_sniff = PacketSniffer()
    pack_sniff.sniffer()