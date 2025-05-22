# src/tp1/utils/capture.py
from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger # Import logger

try:
    from scapy.all import sniff, conf as scapy_conf, ARP, TCP, IP, Raw
    # Importation spécifique des couches pour `haslayer` et le nom
    from scapy.layers.l2 import Ether # ARP is already imported above
    from scapy.layers.inet import IP, TCP, UDP, ICMP # IP, TCP already imported
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    logger.error("Scapy is not installed or couldn't be imported. Network capture will not work.")
    SCAPY_AVAILABLE = False
    # Définir des classes factices pour que le code ne plante pas à l'import si Scapy manque
    class FakeLayer: name = "Fake"
    Ether = IP = TCP = UDP = ARP = ICMP = DNS = Raw = FakeLayer # Added Raw
    def sniff(*args, **kwargs): return [] # Fonction sniff factice
    class scapy_conf: iface = None


class Capture:
    def __init__(self) -> None:
        self.interface: str = choose_interface()
        self.packets: list = []  # Pour stocker les paquets Scapy capturés
        self.protocol_counts: dict = {} # Pour stocker {protocole: nombre}
        self.summary: str = ""
        if not self.interface and SCAPY_AVAILABLE:
            logger.warning("No interface selected/available for capture.")
        elif not SCAPY_AVAILABLE:
            logger.error("Scapy is not available. Cannot proceed with capture.")

    def capture_trafic(self, packet_count: int = 50, timeout: int = 30) -> None:
        """
        Capture network traffic from the selected interface.
        :param packet_count: Number of packets to capture.
        :param timeout: Time in seconds to sniff for. Sniffing stops when
                        packet_count is reached or timeout expires, whichever comes first.
                        If packet_count is 0, it will rely on timeout.
        """
        if not SCAPY_AVAILABLE:
            logger.error("Cannot capture traffic: Scapy is not available.")
            return
        if not self.interface:
            logger.error("Cannot capture traffic: No interface selected.")
            return

        logger.info(f"Starting traffic capture on interface: {self.interface} for {packet_count} packets or {timeout}s...")
        try:
            captured_packets = sniff(iface=self.interface, count=packet_count, timeout=timeout, store=1)
            self.packets.extend(captured_packets)
            logger.info(f"Capture finished. {len(self.packets)} packets captured.")
        except PermissionError:
            logger.error(
                "Permission denied to capture on the interface. "
                "Try running the script with sudo or as administrator."
            )
        except Exception as e:
            logger.error(f"An error occurred during traffic capture: {e}")

    def _get_packet_protocol_name(self, packet) -> str:
        """
        Determines a representative protocol name for a given packet for statistics.
        Prioritizes more specific/application layer protocols.
        """
        if packet.haslayer(DNS): return DNS.name
        if packet.haslayer(TCP): return TCP.name
        if packet.haslayer(UDP): return UDP.name
        if packet.haslayer(ICMP): return ICMP.name
        if packet.haslayer(ARP): return ARP.name
        if packet.haslayer(IP): return IP.name
        if packet.haslayer(Ether): return Ether.name
        return "Other"


    def sort_network_protocols(self) -> None:
        """
        Processes captured packets to count occurrences of each network protocol.
        Populates self.protocol_counts.
        """
        if not SCAPY_AVAILABLE:
            logger.error("Cannot sort protocols: Scapy is not available.")
            return
        if not self.packets:
            logger.info("No packets captured to analyze for protocol statistics.")
            self.protocol_counts = {}
            return

        self.protocol_counts.clear()
        for pkt in self.packets:
            proto_name = self._get_packet_protocol_name(pkt)
            self.protocol_counts[proto_name] = self.protocol_counts.get(proto_name, 0) + 1
        
        logger.info(f"Protocol statistics generated: {self.protocol_counts}")

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with their total packet numbers.
        """
        if not self.protocol_counts and self.packets:
            logger.info("Protocol counts not yet generated, generating now.")
            self.sort_network_protocols()
        return self.protocol_counts

    def analyse(self) -> None: # Removed protocol_filter argument
        """
        Analyse all captured data for basic statistics and potential threats.
        Detects potential ARP Spoofing and basic SQL Injection attempts.
        Updates self.summary with the findings.
        """
        if not SCAPY_AVAILABLE:
            self.summary = "Analysis skipped: Scapy is not available."
            logger.error(self.summary)
            return

        if not self.packets:
            logger.info("No packets to analyze.")
            self.summary = "No packets were captured for analysis."
            # Still call gen_summary to ensure the summary reflects this state.
            self.summary = self.gen_summary([]) # Pass empty threats list
            return

        if not self.protocol_counts:
            self.sort_network_protocols()

        detected_threats = []
        arp_ip_to_mac = {}  # Store known IP-MAC mappings from ARP packets

        # Basic SQLi keywords (for heuristic detection)
        sql_keywords = [
            "select ", "union ", "insert ", "update ", "delete ", "drop ",
            " and ", " or ", "--", ";", "xp_cmdshell", "truncate "
        ]

        for i, pkt in enumerate(self.packets):
            threat_details = {}

            # ARP Spoofing Detection
            if pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                # op=1 (who-has), op=2 (is-at)
                if arp_layer.op == 2:  # ARP Reply ("is-at")
                    src_ip = arp_layer.psrc
                    src_mac = arp_layer.hwsrc
                    if src_ip in arp_ip_to_mac and arp_ip_to_mac[src_ip] != src_mac:
                        threat_details = {
                            "type": "Potential ARP Spoofing",
                            "packet_index": i,
                            "protocol": "ARP",
                            "attacker_ip": src_ip,
                            "attacker_mac": src_mac,
                            "description": (
                                f"ARP reply for IP {src_ip} from new MAC {src_mac}. "
                                f"Previously known MAC was {arp_ip_to_mac[src_ip]}."
                            )
                        }
                        detected_threats.append(threat_details)
                    arp_ip_to_mac[src_ip] = src_mac
            
            # Basic SQL Injection Attempt Detection (Heuristic)
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload_data = ""
                try:
                    payload_data = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                except Exception:
                    pass # Ignore decoding errors

                # Check if payload contains any SQL keywords (case-insensitive)
                if any(keyword in payload_data for keyword in sql_keywords):
                    # Check if it's on a common web or database port
                    is_relevant_port = False
                    attacker_ip_info = "N/A"
                    if pkt.haslayer(IP):
                        attacker_ip_info = pkt[IP].src
                    
                    if pkt[TCP].dport in [80, 8080, 443, 3306, 1433, 5432] or \
                       pkt[TCP].sport in [80, 8080, 443, 3306, 1433, 5432]:
                        is_relevant_port = True

                    if is_relevant_port: # Only flag if on relevant ports and keywords found
                        threat_details = {
                            "type": "Potential SQL Injection Attempt",
                            "packet_index": i,
                            "protocol": "TCP",
                            "attacker_ip": attacker_ip_info,
                            "attacker_mac": pkt[Ether].src if pkt.haslayer(Ether) else "N/A",
                            "description": (
                                f"SQL-like keyword detected in TCP payload on port {pkt[TCP].dport}. "
                                f"Source: {attacker_ip_info}:{pkt[TCP].sport}"
                            )
                        }
                        detected_threats.append(threat_details)
        
        self.summary = self.gen_summary(detected_threats)
        logger.info(f"Analysis complete. Summary generated. Detected threats: {len(detected_threats)}")


    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self, detected_threats: list = None) -> str:
        """
        Generate a detailed summary string from protocol_counts and legitimacy analysis.
        """
        summary_lines = ["Network Traffic Protocol Summary:"]
        if not self.protocol_counts and not self.packets:
            summary_lines.append("  No packets captured or no protocols detected.")
        elif not self.protocol_counts and self.packets:
            summary_lines.append("  Packets captured but no protocol statistics could be generated.")
        else:
            for protocol, count in sorted(self.protocol_counts.items(), key=lambda item: item[1], reverse=True):
                summary_lines.append(f"  - {protocol}: {count} packets")
        
        summary_lines.append("\nTraffic Legitimacy Analysis:")
        if detected_threats:
            summary_lines.append("  The following suspicious activities were detected:")
            for threat in detected_threats:
                summary_lines.append(f"  - Threat Type: {threat.get('type', 'Unknown')}")
                summary_lines.append(f"    Packet Index: {threat.get('packet_index', 'N/A')}")
                summary_lines.append(f"    Protocol: {threat.get('protocol', 'N/A')}")
                if 'attacker_ip' in threat:
                    summary_lines.append(f"    Potential Attacker IP: {threat.get('attacker_ip')}")
                if 'attacker_mac' in threat:
                    summary_lines.append(f"    Potential Attacker MAC: {threat.get('attacker_mac')}")
                summary_lines.append(f"    Description: {threat.get('description', 'No details.')}")
        else:
            if not self.packets:
                summary_lines.append("  No packets were captured to analyze for legitimacy.")
            else:
                summary_lines.append("  Based on the performed checks (ARP Spoofing, basic SQLi patterns), no specific illegitimate traffic was detected. Traffic appears legitimate from this perspective.")
        
        # Note on blocking:
        summary_lines.append("\nNote on Blocking:")
        summary_lines.append("  Automatic blocking of attackers is an advanced feature and has not been implemented.")
        summary_lines.append("  If threats are identified, manual intervention or dedicated security tools are recommended.")

        return "\n".join(summary_lines)