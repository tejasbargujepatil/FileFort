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
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import logging

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

# Secure storage directory
secure_storage_dir = "secure_storage"
os.makedirs(secure_storage_dir, exist_ok=True)

# Logger configuration
logging.basicConfig(
    filename="filefort.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="a"
)

# Encryption utility
def encrypt_file(file_path: str, key: bytes) -> bytes:
    """Encrypt the contents of a file using AES-GCM."""
    try:
        with open(file_path, "rb") as f:
            plaintext = f.read()
        
        iv = os.urandom(12)  # 12 bytes IV for AES-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    except Exception as e:
        logging.error(f"Encryption failed for {file_path}: {e}")
        return None

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

# Application GUI class
class IOCExtractorApp:
    def __init__(self, root, encryption_key: bytes):
        self.root = root
        self.root.title("IOC Extractor and Secure File Processor")
        self.encryption_key = encryption_key
        self.files = []
        self.results = {}
        self.api_key = None
        self.queue = queue.Queue()

        # UI components
        self.create_widgets()

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

    def add_files(self):
        files = filedialog.askopenfilenames(filetypes=[("Supported Files", "*.txt *.csv *.json *.pdf *.html")])
        for file in files:
            if file not in self.files:
                encrypted_path = self.encrypt_and_store(file)
                if encrypted_path:
                    self.files.append(encrypted_path)
                    self.file_listbox.insert(tk.END, encrypted_path)

    def remove_files(self):
        selected_indices = list(self.file_listbox.curselection())
        selected_indices.reverse()
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
        self.result_tree.delete(*self.result_tree.get_children())

        # Start processing in a separate thread
        thread = Thread(target=self._process_files_in_background)
        thread.start()

    def _process_files_in_background(self):
        for file_path in self.files:
            self.process_file(file_path)
            self.progress['value'] += 100
            self.root.update_idletasks()

    def process_file(self, file_path):
        file_type = "text/plain"  # In reality, you'd detect the MIME type here
        text = process_file(file_path, file_type)
        iocs = self.extract_iocs(text)
        for ioc_type, iocs_list in iocs.items():
            for ioc in iocs_list:
                enriched = enrich_with_virustotal(ioc, self.api_key) if self.api_key else {}
                self.result_tree.insert("", "end", values=(ioc_type, ioc))
                logging.info(f"Processed IOC: {ioc} (Type: {ioc_type})")

    def extract_iocs(self, text):
        iocs = {}
        if self.md5_var.get():
            iocs["MD5"] = md5_pattern.findall(text)
        if self.sha1_var.get():
            iocs["SHA1"] = sha1_pattern.findall(text)
        if self.sha256_var.get():
            iocs["SHA256"] = sha256_pattern.findall(text)
        if self.sha512_var.get():
            iocs["SHA512"] = sha512_pattern.findall(text)
        if self.ipv4_var.get():
            iocs["IPv4"] = ipv4_pattern.findall(text)
        if self.domain_var.get():
            iocs["Domain"] = domain_pattern.findall(text)
        if self.url_var.get():
            iocs["URL"] = url_pattern.findall(text)
        if self.email_var.get():
            iocs["Email"] = email_pattern.findall(text)
        if self.mac_var.get():
            iocs["MAC Address"] = mac_pattern.findall(text)
        if self.path_var.get():
            iocs["File Path"] = path_pattern.findall(text)
        return iocs

    def encrypt_and_store(self, file_path):
        """Encrypt the file and save it securely."""
        encrypted_data = encrypt_file(file_path, self.encryption_key)
        if encrypted_data:
            encrypted_path = os.path.join(secure_storage_dir, f"{os.path.basename(file_path)}.enc")
            with open(encrypted_path, "wb") as f:
                f.write(encrypted_data)
            logging.info(f"Encrypted file stored: {encrypted_path}")
            return encrypted_path
        return None

    def export_results(self):
        # Export IOCs to CSV
        with open("iocs.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IOC Type", "IOC"])
            for row in self.result_tree.get_children():
                writer.writerow(self.result_tree.item(row)["values"])
        messagebox.showinfo("Export", "Results exported to iocs.csv.")

# Initialize application
secure_key = sha256(b"super_secret_key").digest()  # Example key
root = tk.Tk()
app = IOCExtractorApp(root, secure_key)
root.mainloop()
