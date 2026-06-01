import os
import hashlib
import base64
import vt
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, scrolledtext

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(4096), b""):
            h.update(b)
    return h.hexdigest()

def scan_file(path, box, label, spinner):
    box.delete(1.0, "end")
    spinner.start()
    label.config(text="Scanning...")

    try:
        with vt.Client(API_KEY) as client:
            file_hash = compute_sha256(path)

            try:
                report = client.get_object(f"/files/{file_hash}")
                stats = report.last_analysis_stats
                box.insert("end", f"File found in VirusTotal!\n")
                for k, v in stats.items():
                    box.insert("end", f"{k.capitalize()}: {v}\n")
                if stats["malicious"] > 0:
                    label.config(text="\u26a0\ufe0f Virus Detected (Malicious)", foreground="red")
                else:
                    label.config(text="\u2705 Safe (No Virus)", foreground="green")
            except vt.error.NotFoundError:
                box.insert("end", "File not found in VirusTotal.\n")
                label.config(text="\u2705 Safe (No Virus)", foreground="green")
    except Exception as e:
        box.insert("end", f"Error: {e}")
        label.config(text="Error", foreground="orange")
    spinner.stop()

def scan_url(url, box, label, spinner):
    box.delete(1.0, "end")
    spinner.start()
    label.config(text="Scanning...")

    try:
        with vt.Client(API_KEY) as client:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            try:
                report = client.get_object(f"/urls/{url_id}")
                stats = report.last_analysis_stats
                box.insert("end", f"URL found in VirusTotal!\n")
                for k, v in stats.items():
                    box.insert("end", f"{k.capitalize()}: {v}\n")
                if stats["malicious"] > 0:
                    label.config(text="\u26a0\ufe0f Virus Detected (Malicious URL)", foreground="red")
                else:
                    label.config(text="\u2705 Safe URL", foreground="green")
            except vt.error.NotFoundError:
                box.insert("end", "URL not found in VirusTotal.\n")
                label.config(text="\u2705 Safe URL", foreground="green")
    except Exception as e:
        box.insert("end", f"Error: {e}")
        label.config(text="Error", foreground="orange")
    spinner.stop()

def browse_and_scan_file(entry, box, label, spinner):
    path = filedialog.askopenfilename()
    if path:
        entry.delete(0, "end")
        entry.insert(0, path)
        scan_file(path, box, label, spinner)

def app_gui():
    app = tb.Window(themename="darkly")
    app.title("Scanner")
    app.geometry("720x500")
    app.resizable(0, 0)

    tabs = tb.Notebook(app)
    tabs.pack(expand=1, fill="both")

    file_tab = tb.Frame(tabs)
    tabs.add(file_tab, text="File Scan")
    file_entry = tb.Entry(file_tab, width=65)
    file_entry.pack(pady=10, padx=10)
    tb.Button(file_tab, text="📂 Browse & Scan", bootstyle="primary", command=lambda: browse_and_scan_file(file_entry, out1, status1, spin1)).pack()
    out1 = scrolledtext.ScrolledText(file_tab, height=18, width=90)
    out1.pack(pady=10)
    status1 = tb.Label(file_tab, text="")
    status1.pack()
    spin1 = tb.Progressbar(file_tab, mode="indeterminate", bootstyle="info")
    spin1.pack()

    url_tab = tb.Frame(tabs)
    tabs.add(url_tab, text="URL Scan")
    url_entry = tb.Entry(url_tab, width=70)
    url_entry.pack(pady=10)
    tb.Button(url_tab, text="🔗 Scan URL", bootstyle="warning", command=lambda: scan_url(url_entry.get(), out2, status2, spin2)).pack()
    out2 = scrolledtext.ScrolledText(url_tab, height=18, width=90)
    out2.pack(pady=10)
    status2 = tb.Label(url_tab, text="")
    status2.pack()
    spin2 = tb.Progressbar(url_tab, mode="indeterminate", bootstyle="info")
    spin2.pack()

    app.mainloop()

if __name__ == "__main__":
    app_gui()
