# src/tp1/utils/report.py
import matplotlib
matplotlib.use('Agg') # Use a non-interactive backend for matplotlib
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import os
from src.tp1.utils.config import logger # Importation du logger

class Report:
    def __init__(self, capture, filename: str, summary_text: str):
        self.capture = capture # The Capture object instance
        self.filename = filename # e.g., "network_traffic_report.pdf"
        self.title = "Network Traffic Analysis Report"
        self.summary_from_capture = summary_text # Pre-generated summary text from Capture.analyse()
        self.graph_image_path = "protocol_distribution_graph.png" # Default path for the graph image
        self.protocol_data_for_table = [] # To store data for ReportLab table

    def _prepare_report_elements(self):
        """Generates graph and prepares table data before PDF creation."""
        self.generate_protocol_graph()
        self.prepare_protocol_table_data()

    def generate_protocol_graph(self):
        """Generates a bar graph of protocol distribution and saves it as an image."""
        if not self.capture.packets:
            logger.warning("No packets captured, skipping graph generation.")
            self.graph_image_path = None # No graph if no packets
            return

        protocol_counts = self.capture.get_all_protocols() 
        
        if not protocol_counts:
            logger.warning("No protocol statistics available to generate graph.")
            self.graph_image_path = None
            return

        string_keyed_protocol_counts = {}
        for key, value in protocol_counts.items():
            if not isinstance(key, str):
                logger.warning(f"Converting non-string protocol key '{repr(key)}' to string '{str(key)}' for plotting.")
                string_keyed_protocol_counts[str(key)] = value
            else:
                string_keyed_protocol_counts[key] = value
        
        if not string_keyed_protocol_counts:
            logger.warning("Protocol counts are empty after attempting to stringify keys. Cannot generate graph.")
            self.graph_image_path = None
            return

        names = list(string_keyed_protocol_counts.keys())
        values = list(string_keyed_protocol_counts.values())
            
        if not names or not values: 
            logger.warning("Protocol names or values are empty after processing. Cannot generate graph.")
            self.graph_image_path = None
            return

        plt.figure(figsize=(10, 6))
        bars = plt.bar(names, values, color=['skyblue', 'lightcoral', 'lightgreen', 'gold', 'lightsalmon', 'cyan', 'violet'])
        plt.xlabel("Protocol")
        plt.ylabel("Number of Packets")
        plt.title("Network Protocol Distribution")
        plt.xticks(rotation=45, ha="right")
        try: 
            if values: 
                 plt.bar_label(bars, fmt='%d') 
        except Exception as e:
            logger.warning(f"Could not add bar labels: {e}")
        plt.tight_layout()

        try:
            plt.savefig(self.graph_image_path)
            logger.info(f"Protocol distribution graph saved as {self.graph_image_path}")
        except Exception as e:
            logger.error(f"Failed to save protocol graph: {e}")
            self.graph_image_path = None 
        finally:
            plt.close() 

    def prepare_protocol_table_data(self):
        """Prepares the data structure for the ReportLab table."""
        if not self.capture.packets:
            logger.warning("No packets captured, skipping table data preparation.")
            self.protocol_data_for_table = []
            return

        protocol_counts = self.capture.get_all_protocols()
        if not protocol_counts:
            logger.warning("No protocol statistics available for table.")
            self.protocol_data_for_table = []
            return
        
        self.protocol_data_for_table = [["Protocol", "Packet Count"]]
        for key, count in sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True):
            display_key = str(key) if not isinstance(key, str) else key
            self.protocol_data_for_table.append([display_key, str(count)])
        logger.info("Protocol data for table prepared.")

    def save(self) -> None:
        """Saves the full report as a PDF file."""
        self._prepare_report_elements() 

        doc = SimpleDocTemplate(self.filename, pagesize=(8.5 * inch, 11 * inch),
                                topMargin=0.5*inch, bottomMargin=0.5*inch,
                                leftMargin=0.75*inch, rightMargin=0.75*inch)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = styles['h1']
        title_style.alignment = TA_CENTER
        story.append(Paragraph(self.title, title_style))
        story.append(Spacer(1, 0.3 * inch))

        # Analysis Summary
        story.append(Paragraph("<b>I. Analysis Summary</b>", styles['h2']))
        summary_body_style = ParagraphStyle('summaryBody', parent=styles['Normal'], spaceBefore=6, leading=14)
        summary_text_for_pdf = self.summary_from_capture.replace("\n", "<br/>")
        story.append(Paragraph(summary_text_for_pdf, summary_body_style))
        story.append(Spacer(1, 0.3 * inch))

        # Protocol Statistics Table
        story.append(Paragraph("<b>II. Protocol Statistics</b>", styles['h2']))
        if self.protocol_data_for_table:
            story.append(Paragraph("The table below lists all network protocols detected during the capture and the corresponding number of packets for each.", summary_body_style))
            story.append(Spacer(1, 0.1 * inch))
            
            table = Table(self.protocol_data_for_table, colWidths=[3 * inch, 2 * inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#4F81BD")), 
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#DCE6F1")), 
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#7F7F7F")),
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No protocol data available to generate a table (e.g., no packets captured).", summary_body_style))
        story.append(Spacer(1, 0.3 * inch))

        # Protocol Distribution Graph
        story.append(Paragraph("<b>III. Protocol Distribution Graph</b>", styles['h2']))
        if self.graph_image_path and os.path.exists(self.graph_image_path):
            story.append(Paragraph("The bar chart below visually represents the distribution of captured packets by protocol.", summary_body_style))
            story.append(Spacer(1, 0.1 * inch))
            try:
                img_width = 6.5 * inch 
                img = Image(self.graph_image_path, width=img_width, height=(img_width * 0.6)) 
                story.append(img)
            except Exception as e:
                logger.error(f"Could not embed graph image '{self.graph_image_path}' into PDF: {e}")
                story.append(Paragraph(f"[Error loading graph image: {e}]", styles['Normal']))
        else:
            story.append(Paragraph("The protocol distribution graph could not be generated or included (e.g., no packets captured or an error occurred).", summary_body_style))

        try:
            doc.build(story)
            logger.info(f"PDF Report successfully saved to {self.filename}")
        except Exception as e:
            logger.error(f"Failed to build PDF report: {e}")
            txt_fallback_filename = self.filename.replace(".pdf", "_fallback.txt")
            try:
                with open(txt_fallback_filename, "w") as f_fallback:
                    f_fallback.write(f"Title: {self.title}\n\n")
                    f_fallback.write(self.summary_from_capture)
                logger.info(f"Fallback text summary saved to {txt_fallback_filename}")
            except Exception as e_fallback:
                logger.error(f"Failed to save fallback text summary: {e_fallback}")