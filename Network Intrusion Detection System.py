import os 
import hashlib
import vt
import threading
from scapy.all import sniff, Raw, get_if_list, wrpcap, IP, TCP, UDP, DNSQR, DNSRR, DNS
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from plyer import notification
import json

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

SUSPICIOUS_KEYWORDS = ["cmd.exe", "powershell", "nc.exe", "/bin/sh", "bash", "TEST_THREAT"]

sniffing = False
selected_interface = None
packet_list = []
total_packets = 0
suspicious_packets = 0


def log_alert(alert_msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {alert_msg}\n"
    with open("nids_alerts.log", "a") as f:
        f.write(full_msg)
    output_text.insert(tk.END, full_msg)
    output_text.see(tk.END)


def show_notification(title, message):
    notification.notify(title=title, message=message, timeout=5)


def update_stats():
    stats_label.config(text=f"Packets Captured: {total_packets} | Suspicious Detected: {suspicious_packets}")


def check_payload(payload):
    global suspicious_packets
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in payload:
            log_alert(f"Suspicious keyword found in payload: '{keyword}'")
            show_notification("Suspicious Packet Detected", keyword)
            return True
    return False


def detect_dns_tunneling(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode(errors='ignore')
        if len(query) > 50 and query.count('.') > 5:
            log_alert(f"Potential DNS tunneling detected: {query}")
            show_notification("Potential DNS Tunneling", query)
            return True
    return False


def detect_port_scan(pkt):
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags == 2:  # SYN flag
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dst_port = pkt[TCP].dport
            log_alert(f"Port scan probe (SYN) from {src_ip} to {dst_ip}:{dst_port}")
            return True
    return False


def query_virustotal_hash(data_bytes):
    if not API_KEY:
        log_alert("VirusTotal Scan Skipped: VIRUSTOTAL_API_KEY environment variable is not set.")
        return
    
    file_hash = hashlib.sha256(data_bytes).hexdigest()
    try:
        with vt.Client(API_KEY) as client:
            try:
                file_info = client.get_object(f"/files/{file_hash}")
                malicious = file_info.last_analysis_stats.get("malicious", 0)
                if malicious > 0:
                    log_alert(f"VirusTotal flagged hash ({file_hash}) with {malicious} detections.")
                    show_notification("VirusTotal Alert", f"{malicious} detections for {file_hash}")
                else:
                    log_alert(f"Hash checked clean: {file_hash}")
            except vt.error.APIError:
                log_alert(f"Hash not found in VirusTotal: {file_hash}")
    except Exception as e:
        log_alert(f"VirusTotal query failed: {e}")


def get_protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(IP):
        return "IP"
    return "Other"


def process_packet(packet):
    global total_packets, suspicious_packets
    total_packets += 1
    update_stats()
    packet_list.append(packet)

    src = packet[IP].src if packet.haslayer(IP) else "N/A"
    dst = packet[IP].dst if packet.haslayer(IP) else "N/A"
    proto = get_protocol(packet)
    length = len(packet)
    row_color = 'green'

    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            if check_payload(payload):
                suspicious_packets += 1
                update_stats()
                row_color = 'red'
                threading.Thread(target=query_virustotal_hash, args=(packet[Raw].load,), daemon=True).start()
        except Exception as e:
            log_alert(f"Payload decoding error: {e}")

    if detect_dns_tunneling(packet):
        row_color = 'red'
        suspicious_packets += 1
        update_stats()

    if detect_port_scan(packet):
        row_color = 'red'
        suspicious_packets += 1
        update_stats()

    packet_table.insert('', 'end', values=(src, dst, proto, length), tags=(row_color,))
    packet_table.yview_moveto(1.0)


def sniff_packets():
    try:
        sniff(prn=process_packet, store=0, iface=selected_interface, stop_filter=lambda x: not sniffing)
    except Exception as e:
        log_alert(f"Failed to start sniffing: {e}")


def start_nids():
    global sniffing, selected_interface, total_packets, suspicious_packets, packet_list
    selected_interface = iface_combo.get()
    if not selected_interface:
        messagebox.showerror("Error", "Please select a network interface.")
        return
    sniffing = True
    total_packets = 0
    suspicious_packets = 0
    packet_list = []
    update_stats()
    threading.Thread(target=sniff_packets, daemon=True).start()
    log_alert(f"NIDS started on interface: {selected_interface}")


def stop_nids():
    global sniffing
    sniffing = False
    log_alert("NIDS stopped.")
    if packet_list:
        wrpcap("captured_traffic.pcap", packet_list)
        log_alert("Captured traffic saved to captured_traffic.pcap")
        show_notification("PCAP Saved", "Traffic saved to captured_traffic.pcap")

# GUI Setup
root = tk.Tk()
root.title("Python NIDS - Full Enterprise Mode")
root.geometry("1100x750")
root.configure(bg="#2b2b2b")

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#1e1e1e", foreground="white", rowheight=25, fieldbackground="#1e1e1e")
style.configure("Treeview.Heading", background="#444", foreground="white", font=('Arial', 10, 'bold'))
style.map('Treeview', background=[('selected', '#097cfd')])

from scapy.all import get_if_list
interfaces = get_if_list()
default_interface = None
for iface in interfaces:
    if ("wi-fi" in iface.lower() or "wlan" in iface.lower() or "wireless" in iface.lower()) and "virtual" not in iface.lower():
        default_interface = iface
        break

iface_label = tk.Label(root, text="Select Network Interface:", font=("Arial", 10), bg="#2b2b2b", fg="white")
iface_label.pack(pady=5)
iface_combo = ttk.Combobox(root, values=interfaces, width=50)
iface_combo.pack(pady=5)
iface_combo.set(default_interface if default_interface else interfaces[0] if interfaces else "")

start_btn = tk.Button(root, text="Start Monitoring", command=start_nids, bg="#4caf50", fg="white", font=("Arial", 12), width=20)
start_btn.pack(pady=10)

stop_btn = tk.Button(root, text="Stop Monitoring", command=stop_nids, bg="#f44336", fg="white", font=("Arial", 12), width=20)
stop_btn.pack(pady=5)

stats_label = tk.Label(root, text="Packets Captured: 0 | Suspicious Detected: 0", font=("Arial", 10), fg="yellow", bg="#2b2b2b")
stats_label.pack(pady=5)

output_text = scrolledtext.ScrolledText(root, width=100, height=10, font=("Courier", 10), bg="#1e1e1e", fg="white")
output_text.pack(padx=10, pady=10)

packet_frame = tk.Frame(root, bg="#2b2b2b")
packet_frame.pack(padx=10, pady=5, fill="both", expand=True)

columns = ("Source", "Destination", "Protocol", "Length")
packet_table = ttk.Treeview(packet_frame, columns=columns, show='headings', height=15)
for col in columns:
    packet_table.heading(col, text=col)
    packet_table.column(col, anchor='center', width=180)

packet_table.tag_configure('red', background='#ff4c4c')
packet_table.tag_configure('green', background='#4caf50')

packet_table.pack(fill="both", expand=True)

scrollbar = ttk.Scrollbar(packet_frame, orient="vertical", command=packet_table.yview)
packet_table.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side='right', fill='y')

root.mainloop()
