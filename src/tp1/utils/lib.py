# src/tp1/utils/lib.py
from src.tp1.utils.config import logger # Assurez-vous que logger est accessible
# Utilisez scapy.arch pour lister les interfaces de manière portable
# Si scapy n'est pas encore une dépendance principale ici, vous pourriez utiliser psutil
# mais puisque le projet utilise Scapy, c'est cohérent.
try:
    from scapy.arch import get_if_list, conf as scapy_conf
except ImportError:
    logger.error("Scapy is not installed. Please install it: pip install scapy")
    # Fournir des implémentations factices pour que le reste du code puisse être importé
    # sans crasher immédiatement, bien que la fonctionnalité principale sera cassée.
    def get_if_list(): return []
    class scapy_conf: iface = None


def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice.
    """
    try:
        interfaces = get_if_list()
        if not interfaces:
            logger.warning("Scapy could not find any interfaces.")
            # Tenter d'utiliser l'interface par défaut de Scapy si elle est définie
            if scapy_conf.iface:
                logger.info(f"Using Scapy's default interface: {scapy_conf.iface}")
                return str(scapy_conf.iface) # scapy_conf.iface peut être un objet Interface
            logger.error("No network interfaces available to choose from.")
            return ""

        print("\nAvailable network interfaces:")
        for i, iface_name in enumerate(interfaces):
            print(f"  {i}: {iface_name}")

        default_iface_name = str(scapy_conf.iface) if scapy_conf.iface else interfaces[0] if interfaces else ""
        prompt_msg = f"Choose interface number (0-{len(interfaces)-1}) or press Enter for default ('{default_iface_name}'): "

        while True:
            try:
                choice_str = input(prompt_msg).strip()
                if not choice_str: # User pressed Enter
                    selected_interface = default_iface_name
                    if not selected_interface:
                         logger.error("No default interface and no selection made.")
                         return ""
                    logger.info(f"Using default interface: {selected_interface}")
                    return selected_interface
                
                choice_idx = int(choice_str)
                if 0 <= choice_idx < len(interfaces):
                    selected_interface = interfaces[choice_idx]
                    logger.info(f"Interface selected: {selected_interface}")
                    return selected_interface
                else:
                    print(f"Invalid choice. Please enter a number between 0 and {len(interfaces)-1}.")
            except ValueError:
                print("Invalid input. Please enter a number or press Enter for default.")
            except Exception as e:
                logger.error(f"Error during interface selection: {e}")
                return default_iface_name # Fallback to default on unexpected error
    except Exception as e:
        logger.error(f"Could not list network interfaces: {e}. Check Scapy installation and permissions.")
        return ""