# main.py
from src.tp1.utils.capture import Capture
from src.tp1.utils.capture import SCAPY_AVAILABLE
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report
import os # For checking if file exists


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

    # Consider making these configurable or command-line arguments for more flexibility
    num_packets_to_capture = 100 # As per original example
    capture_timeout_seconds = 30  # As per original example

    logger.info(f"Attempting to capture {num_packets_to_capture} packets or for {capture_timeout_seconds} seconds.")
    capture.capture_trafic(packet_count=num_packets_to_capture, timeout=capture_timeout_seconds)

    if not capture.packets:
        logger.warning("No packets were captured. The report might be incomplete or state this fact.")
    else:
        logger.info(f"Successfully captured {len(capture.packets)} packets.")

    logger.info("Analyzing captured traffic (including legitimacy checks)...")
    # analyse() now internally handles protocol statistics and legitimacy, then generates the full summary.
    capture.analyse() 

    # Get the comprehensive summary (which includes legitimacy analysis)
    report_summary_text = capture.get_summary()

    # Log the summary to console for immediate feedback
    logger.info("--- CAPTURE SUMMARY (for console) ---")
    for line in report_summary_text.splitlines():
        logger.info(line)
    logger.info("--- END CAPTURE SUMMARY (for console) ---")

    report_filename_pdf = "network_traffic_report.pdf" # Changed to .pdf extension

    # Instantiate Report with the capture object, desired PDF filename, and the generated summary
    report_instance = Report(capture, report_filename_pdf, report_summary_text)

    logger.info(f"Generating and saving PDF report to {report_filename_pdf}...")
    # The save() method in Report class now handles graph generation, table data prep, and PDF building.
    report_instance.save() 
    
    # Verify report creation
    if os.path.exists(report_instance.filename):
        logger.info(f"Report generation process complete. Output: {report_instance.filename}")
        print(f"\nNetwork Traffic Analysis Report generated: {report_instance.filename}")
        if report_instance.graph_image_path and os.path.exists(report_instance.graph_image_path):
             print(f"Graph image saved at: {report_instance.graph_image_path}")
    else:
        logger.error(f"PDF Report file {report_instance.filename} was NOT created. Check logs for errors.")
        print(f"\nReport generation FAILED. Check logs for details.")


if __name__ == "__main__":
    main()