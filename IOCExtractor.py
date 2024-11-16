import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.simpledialog import askstring
from tkinter import Toplevel
import json
import csv
import pdfplumber
import re
import requests
from threading import Thread
import time
import webbrowser
import queue

# Define regex patterns for IOCs
md5_pattern = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
sha1_pattern = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
sha256_pattern = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
sha512_pattern = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{128}(?![0-9a-fA-F])")
ipv4_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b")
domain_pattern = re.compile(r"(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}")
url_pattern = re.compile(r"https?://(?:[A-Za-z0-9\-]+\.)+[A-Za-z0-9]{2,}(?::\d{1,5})?[/A-Za-z0-9\-%?=\+\.]*")
email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
mac_pattern = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
path_pattern = re.compile(r"[a-zA-Z]:\\(?:[\w\s]+\\)*\w+\.\w+|\/(?:[\w\s]+\/)*\w+\.\w+")

# Define text extraction functions
def get_pdf_text(pdf_path: str) -> str:
    try:
        with pdfplumber.open(pdf_path) as pdf:
            return "".join([p.extract_text() or "" for p in pdf.pages])
    except Exception as e:
        return f"Error extracting text from PDF: {e}"

def process_file(file_path: str, file_type: str) -> str:
    try:
        if file_type == "application/pdf":
            return get_pdf_text(file_path)
        else:
            with open(file_path, "r", encoding="utf-8") as file:
                return file.read()
    except Exception as e:
        return f"Error processing file {file_path}: {e}"

# Function to enrich IOCs with VirusTotal API
def enrich_with_virustotal(ioc: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{ioc}" if len(ioc) == 64 else f"https://www.virustotal.com/api/v3/urls/{ioc}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": "Failed to enrich IOC"}

# GUI class
class IOCExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IOC Extractor")
        self.root.geometry("900x650")

        # File list
        self.files = []
        self.results = {}
        self.api_key = None
        self.queue = queue.Queue()

        # Add menu bar
        self.create_menu()

        # UI components
        self.create_widgets()

        # Process results from thread
        self.root.after(100, self.process_queue)

    def create_menu(self):
        menu_bar = tk.Menu(self.root)

        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Add Files", command=self.add_files)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Contact menu
        contact_menu = tk.Menu(menu_bar, tearoff=0)
        contact_menu.add_command(label="Contact Developer", command=self.open_contact)
        menu_bar.add_cascade(label="Contact", menu=contact_menu)

        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Instructions", command=self.show_instructions)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        # Attach the menu to the root window
        self.root.config(menu=menu_bar)

    def open_contact(self):
        # Open GitHub and Instagram links in browser
        webbrowser.open("https://github.com/tejasbargujepatil")
        webbrowser.open("https://instagram.com/Tejas_Barguje_Patil")

    def show_instructions(self):
        # Show instructions in a message box
        instructions = """
        1. Add Files: Use this option to add text, CSV, PDF, HTML, or JSON files.
        2. Select IOC Types: Choose which types of IOCs (Indicators of Compromise) to extract using checkboxes.
        3. Set API Key: If you want Threat Enrichment, enter your VirusTotal API key.
        4. Process Files: After adding files and selecting IOC types, click this button to start processing.
        5. View Results: The results are displayed in the table. Each IOC type will show associated matches.
        6. Export: Export the results to CSV or JSON format.
        """
        messagebox.showinfo("Help - Instructions", instructions)

    def set_api_key(self):
        self.api_key = askstring("API Key", "Enter your VirusTotal API Key:")
        if not self.api_key:
            messagebox.showerror("Error", "API Key is required for Threat Enrichment.")

    def add_files(self):
        files = filedialog.askopenfilenames(filetypes=[("Supported Files", "*.txt *.csv *.json *.pdf *.html")])
        for file in files:
            if file not in self.files:
                self.files.append(file)
                self.file_listbox.insert(tk.END, file)

    def remove_files(self):
        selected_indices = list(self.file_listbox.curselection())
        selected_indices.reverse()  # Remove from bottom to avoid index shifting
        for idx in selected_indices:
            self.file_listbox.delete(idx)
            self.files.pop(idx)

    def process_files(self):
        if not self.files:
            messagebox.showerror("Error", "No files to process.")
            return

        # Reset progress bar
        self.progress['value'] = 0
        self.progress['maximum'] = len(self.files) * 100
        self.result_tree.delete(*self.result_tree.get_children())  # Clear old results

        # Start processing in a separate thread
        thread = Thread(target=self._process_files)
        thread.start()

    def _process_files(self):
        for file in self.files:
            file_type = file.split('.')[-1].lower()
            content = process_file(file, file_type)
            self.extract_iocs(file, content)
            self.progress['value'] += 100
            time.sleep(0.1)  # Simulate work

    def extract_iocs(self, file, content):
        iocs = {
            "md5": md5_pattern.findall(content) if self.md5_var.get() else [],
            "sha1": sha1_pattern.findall(content) if self.sha1_var.get() else [],
            "sha256": sha256_pattern.findall(content) if self.sha256_var.get() else [],
            "sha512": sha512_pattern.findall(content) if self.sha512_var.get() else [],
            "ipv4": ipv4_pattern.findall(content) if self.ipv4_var.get() else [],
            "domain": domain_pattern.findall(content) if self.domain_var.get() else [],
            "url": url_pattern.findall(content) if self.url_var.get() else [],
            "email": email_pattern.findall(content) if self.email_var.get() else [],
            "mac": mac_pattern.findall(content) if self.mac_var.get() else [],
            "path": path_pattern.findall(content) if self.path_var.get() else []
        }

        self.results[file] = iocs

        # Update GUI with results
        self.queue.put(iocs)

    def process_queue(self):
        try:
            iocs = self.queue.get_nowait()
            for ioc_type, iocs_list in iocs.items():
                for ioc in iocs_list:
                    self.result_tree.insert('', 'end', values=(ioc_type, ioc))
        except queue.Empty:
            pass

        self.root.after(100, self.process_queue)

    def create_widgets(self):
        # IOC type checkboxes
        self.md5_var = tk.BooleanVar()
        self.sha1_var = tk.BooleanVar()
        self.sha256_var = tk.BooleanVar()
        self.sha512_var = tk.BooleanVar()
        self.ipv4_var = tk.BooleanVar()
        self.domain_var = tk.BooleanVar()
        self.url_var = tk.BooleanVar()
        self.email_var = tk.BooleanVar()
        self.mac_var = tk.BooleanVar()
        self.path_var = tk.BooleanVar()

        # Create checkboxes for IOC types
        self.checkbox_frame = tk.Frame(self.root)
        self.checkbox_frame.pack(fill=tk.X)

        self.create_checkbox("MD5", self.md5_var)
        self.create_checkbox("SHA1", self.sha1_var)
        self.create_checkbox("SHA256", self.sha256_var)
        self.create_checkbox("SHA512", self.sha512_var)
        self.create_checkbox("IPv4", self.ipv4_var)
        self.create_checkbox("Domain", self.domain_var)
        self.create_checkbox("URL", self.url_var)
        self.create_checkbox("Email", self.email_var)
        self.create_checkbox("MAC Address", self.mac_var)
        self.create_checkbox("File Path", self.path_var)

        # File Listbox
        self.file_listbox = tk.Listbox(self.root, selectmode=tk.MULTIPLE, height=8)
        self.file_listbox.pack(fill=tk.BOTH, padx=10, pady=10)

        # Buttons
        self.add_button = tk.Button(self.root, text="Add Files", command=self.add_files)
        self.add_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.remove_button = tk.Button(self.root, text="Remove Files", command=self.remove_files)
        self.remove_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.process_button = tk.Button(self.root, text="Process Files", command=self.process_files)
        self.process_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.export_button = tk.Button(self.root, text="Export Results", command=self.export_results)
        self.export_button.pack(side=tk.LEFT, padx=10, pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, length=200, mode="determinate")
        self.progress.pack(padx=10, pady=10)

        # Result Treeview
        self.result_tree = ttk.Treeview(self.root, columns=("IOC Type", "IOC"), show="headings")
        self.result_tree.heading("IOC Type", text="IOC Type")
        self.result_tree.heading("IOC", text="IOC")
        self.result_tree.pack(fill=tk.BOTH, padx=10, pady=10)

    def create_checkbox(self, text, var):
        checkbox = tk.Checkbutton(self.checkbox_frame, text=text, variable=var)
        checkbox.pack(side=tk.LEFT, padx=5, pady=5)

    def export_results(self):
        if not self.results:
            messagebox.showerror("Error", "No results to export.")
            return

        export_type = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv")])

        if export_type.endswith(".json"):
            with open(export_type, "w") as json_file:
                json.dump(self.results, json_file, indent=4)

        elif export_type.endswith(".csv"):
            with open(export_type, "w", newline="") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["File", "IOC Type", "IOC"])
                for file, iocs in self.results.items():
                    for ioc_type, iocs_list in iocs.items():
                        for ioc in iocs_list:
                            writer.writerow([file, ioc_type, ioc])

# Run the application
root = tk.Tk()
app = IOCExtractorApp(root)
root.mainloop()
