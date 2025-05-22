# main.py
from src.tp1.utils.capture import Capture
from src.tp1.utils.capture import SCAPY_AVAILABLE
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report


def main():
    logger.info("Starting TP1 Network Analyzer")
    capture = Capture()

    if not capture.interface or not SCAPY_AVAILABLE:
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not available or could not be imported. Please check installation.")
        if not capture.interface:
            logger.error("No network interface was selected or available.")
        logger.error("Cannot proceed. Exiting.")
        return

    logger.info(f"Using interface: {capture.interface} for capture.")

    num_packets_to_capture = 100
    capture_timeout_seconds = 30

    logger.info(f"Attempting to capture {num_packets_to_capture} packets or for {capture_timeout_seconds} seconds.")
    capture.capture_trafic(packet_count=num_packets_to_capture, timeout=capture_timeout_seconds)

    if not capture.packets:
        logger.warning("No packets were captured. The report might be empty or incomplete.")
    else:
        logger.info(f"Successfully captured {len(capture.packets)} packets.")

    logger.info("Analyzing captured traffic...")
    # MODIFICATION ICI pour correspondre à la définition dans capture.py
    capture.analyse(protocol_filter="tcp")

    summary_text = capture.get_summary()

    logger.info("--- CAPTURE SUMMARY ---")
    for line in summary_text.splitlines():
        logger.info(line)
    logger.info("--- END CAPTURE SUMMARY ---")

    report_filename = "network_traffic_report.txt"
    report_instance = Report(capture, report_filename, summary_text)

    logger.info("Generating report components (graph and array placeholders)...")
    report_instance.generate("graph")
    report_instance.generate("array")

    logger.info(f"Saving report to {report_filename}...")
    report_instance.save(report_filename)
    logger.info(f"Report successfully saved to {report_instance.filename}.")
    print(f"\nReport generated: {report_instance.filename}")


if __name__ == "__main__":
    main()