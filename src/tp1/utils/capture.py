# src/tp1/utils/capture.py
from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger # Import logger

try:
    from scapy.all import sniff, conf as scapy_conf
    # Importation spécifique des couches pour `haslayer` et le nom
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    logger.error("Scapy is not installed or couldn't be imported. Network capture will not work.")
    SCAPY_AVAILABLE = False
    # Définir des classes factices pour que le code ne plante pas à l'import si Scapy manque
    class FakeLayer: name = "Fake"
    Ether = IP = TCP = UDP = ARP = ICMP = DNS = FakeLayer
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
            # `stop_filter` could be used for more complex stopping conditions.
            # Using `count` and `timeout` for simplicity as per common Scapy usage.
            # Scapy's sniff needs to run with appropriate permissions (often root/admin).
            captured_packets = sniff(iface=self.interface, count=packet_count, timeout=timeout, store=1)
            self.packets.extend(captured_packets) # Use extend if calling multiple times, or =
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
        # Priorité (modifiable selon les besoins)
        if packet.haslayer(DNS): return DNS.name # DNS
        # Ajouter ici d'autres protocoles applicatifs si besoin (HTTP, TLS, etc.)
        # Pour HTTP, il faudrait vérifier les ports TCP (80, 443 pour HTTPS)
        # Ex: if packet.haslayer(TCP) and (packet[TCP].sport == 80 or packet[TCP].dport == 80): return "HTTP"
        
        if packet.haslayer(TCP): return TCP.name # TCP
        if packet.haslayer(UDP): return UDP.name # UDP (si pas déjà DNS etc.)
        if packet.haslayer(ICMP): return ICMP.name # ICMP
        if packet.haslayer(ARP): return ARP.name # ARP
        if packet.haslayer(IP): return IP.name   # IP (générique si rien d'autre au-dessus)
        if packet.haslayer(Ether): return Ether.name # Ethernet (si rien d'autre)
        return "Other"


    def sort_network_protocols(self) -> None:
        """
        Processes captured packets to count occurrences of each network protocol.
        Populates self.protocol_counts.
        This method name is per the original skeleton; "process_packets_for_stats" might be more descriptive.
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
        # La fonction ne retourne rien selon le squelette, elle modifie self.protocol_counts

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with their total packet numbers.
        """
        if not self.protocol_counts and self.packets:
            logger.info("Protocol counts not yet generated, generating now.")
            self.sort_network_protocols() # Ensure counts are populated if packets exist
        return self.protocol_counts

    def analyse(self, protocol_filter: str = None) -> None:
        """
        Analyse all captured data and return statement.
        Si un trafic est illégitime (exemple : Injection SQL, ARP Spoofing, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine attaquante.
        Sinon afficher que tout va bien.

        For now, this method will populate the summary based on protocol counts.
        The `protocol_filter` might be used later for deeper analysis of a specific protocol.
        """
        if not SCAPY_AVAILABLE:
            self.summary = "Analysis skipped: Scapy is not available."
            logger.error(self.summary)
            return

        # S'assurer que les comptes de protocoles sont faits
        if not self.protocol_counts and self.packets:
            self.sort_network_protocols()
        elif not self.packets:
            logger.info("No packets to analyze.")
            self.summary = "No packets were captured for analysis."
            return

        # La logique d'analyse d'attaque viendra ici plus tard.
        # Pour l'instant, générons un résumé simple.
        self.summary = self.gen_summary()
        logger.info(f"Analysis complete. Summary generated. First 100 chars: '{self.summary[:100]}...'")


    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate a basic summary string from protocol_counts.
        Later, this will include results from the `analyse` method's legitimacy checks.
        """
        if not self.protocol_counts:
            return "No protocol statistics available to generate summary."

        summary_lines = ["Network Traffic Protocol Summary:"]
        if not self.protocol_counts:
            summary_lines.append("  No protocols detected or no packets captured.")
        else:
            for protocol, count in sorted(self.protocol_counts.items(), key=lambda item: item[1], reverse=True):
                summary_lines.append(f"  - {protocol}: {count} packets")
        
        # Placeholder for attack analysis results
        summary_lines.append("\nTraffic Legitimacy Analysis:")
        summary_lines.append("  Analysis for specific threats (SQLi, ARP Spoofing, etc.) TBD.")
        summary_lines.append("  Currently, all traffic is assumed legitimate for basic stats.")
        # Plus tard, on ajoutera ici les résultats de l'analyse de légitimité.

        return "\n".join(summary_lines)