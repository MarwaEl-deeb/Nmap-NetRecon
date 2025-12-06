# main.py
import customtkinter as ctk
from tkinter import filedialog, messagebox
from nmap_runner import NmapRunner
from report import ReportManager
import threading
import queue

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NmapGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Nmap NetRecon")
        self.geometry("1000x700")

        self.runner = NmapRunner()
        self.report = ReportManager()
        self.last_command = ""
        self.iL_file = ""
        self.scan_queue = queue.Queue()

        self.build_ui()
        self.poll_queue()

    def build_ui(self):
        # Scrollable sidebar
        sidebar_container = ctk.CTkFrame(self, width=250, corner_radius=20)
        sidebar_container.pack(side="left", fill="y", padx=10, pady=10)

        self.sidebar = ctk.CTkScrollableFrame(sidebar_container, corner_radius=20)
        self.sidebar.pack(fill="both", expand=True)

        # Header
        ctk.CTkLabel(self.sidebar, text="Nmap NetRecon", font=("Arial", 24, "bold")).pack(pady=15)

        # Target
        ctk.CTkLabel(self.sidebar, text="Target IP / Domain", font=("Arial", 14)).pack(pady=2)
        self.target_entry = ctk.CTkEntry(self.sidebar, corner_radius=10, width=200)
        self.target_entry.pack(pady=2)

        # Scan Technique
        ctk.CTkLabel(self.sidebar, text="Scan Technique").pack(pady=5)
        self.scan_menu = ctk.CTkComboBox(
            self.sidebar,
            values=["", "-v", "-iL", "-sS", "-sT", "-sU", "-sA", "-sW", "-sM", "--randomize-hosts -iR", "--exclude"],
            command=self.scan_changed
        )
        self.scan_menu.pack(pady=2)

        # Dynamic input fields (initially hidden)
        self.iL_button = ctk.CTkButton(self.sidebar, text="Select -iL File", corner_radius=15,
                                       command=self.choose_iL_file)
        self.iL_label = ctk.CTkLabel(self.sidebar, text="", font=("Arial", 10))

        self.random_count_entry = ctk.CTkEntry(self.sidebar, placeholder_text="No. Random hosts", width=140)
        self.exclude_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Exclude hosts (comma-separated)", width=200)

        # Ports
        ctk.CTkLabel(self.sidebar, text="Ports").pack(pady=2)
        self.ports_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Port numbers or count", width=140)
        self.ports_entry.pack(pady=2)

        ctk.CTkLabel(self.sidebar, text="Port Specification").pack(pady=2)
        self.ports_combo = ctk.CTkComboBox(
            self.sidebar, values=["", "-p-", "-F", "--top-ports", "--exclude-ports"], width=140,
            command=self.port_option_changed
        )
        self.ports_combo.pack(pady=2)

        # Host discovery
        ctk.CTkLabel(self.sidebar, text="Host Discovery").pack(pady=2)
        self.host_menu = ctk.CTkComboBox(self.sidebar, values=["", "-sL", "-sn", "-Pn", "-PS", "-PA", "-PU", "-PR"])
        self.host_menu.pack(pady=2)

        # Version detection
        ctk.CTkLabel(self.sidebar, text="Service / Version Detection").pack(pady=2)
        self.version_menu = ctk.CTkComboBox(
            self.sidebar,
            values=["", "-sV", "-O", "-A", "-sV --version-all", "-sV -O",
                    "-O --osscan-limit", "-O --osscan-guess",
                    "--version-intensity", "--version-light", "--max-os-tries"],
            command=self.version_option_changed
        )
        self.version_menu.pack(pady=2)

        self.version_value_entry = ctk.CTkEntry(self.sidebar, width=140)
        self.version_value_entry.pack_forget()

        # Timing
        ctk.CTkLabel(self.sidebar, text="Timing Template").pack(pady=2)
        self.timing_menu = ctk.CTkComboBox(self.sidebar, values=["", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5"])
        self.timing_menu.pack(pady=2)

        # NSE Script
        ctk.CTkLabel(self.sidebar, text="NSE Script").pack(pady=2)
        self.script_entry = ctk.CTkComboBox(self.sidebar, values=[
            "", "-sC","--script default", "--script=banner", "--script=http", 
            "--script=http,banner", '--script"not intrusive"'])
        self.script_entry.pack(pady=2)

        # Evasion
        ctk.CTkLabel(self.sidebar, text="Firewall / IDS Evasion").pack(pady=2)
        self.evasion_menu = ctk.CTkComboBox(self.sidebar, values=["", "-f", "-D", "-S"])
        self.evasion_menu.pack(pady=2)

        # Buttons (keep reference for packing dynamic fields before them)
        self.run_button = ctk.CTkButton(self.sidebar, text="Run Scan", corner_radius=15, command=self.start_scan)
        self.run_button.pack(pady=(20,5))
        self.save_button = ctk.CTkButton(self.sidebar, text="Save Report", corner_radius=15, command=self.save_report)
        self.save_button.pack(pady=(10,0))

        # Output
        self.output_box = ctk.CTkTextbox(self, corner_radius=15, font=("Consolas", 14))
        self.output_box.pack(fill="both", expand=True, padx=15, pady=15)

    # ---------------- Dynamic Field Handlers ----------------
    def scan_changed(self, choice):
        # Hide all dynamic fields first
        self.iL_button.pack_forget()
        self.iL_label.pack_forget()
        self.random_count_entry.pack_forget()
        self.exclude_entry.pack_forget()
        self.target_entry.configure(state="normal")

        if choice == "-iL":
            self.target_entry.configure(state="disabled")
            self.iL_button.pack(after=self.save_button, pady=2)
            self.iL_label.pack(after=self.save_button, pady=2)
        elif choice == "--randomize-hosts -iR":
            self.target_entry.configure(state="disabled")
            self.random_count_entry.pack(before=self.run_button, pady=2)
        elif choice == "--exclude":
            self.exclude_entry.pack(before=self.run_button, pady=2)

    def port_option_changed(self, choice):
        if choice in ["-p-", "-F"]:
            self.ports_entry.delete(0, "end")
            self.ports_entry.configure(state="disabled")
        else:
            self.ports_entry.configure(state="normal", placeholder_text="Enter number or ports")

    def version_option_changed(self, choice):
        self.version_value_entry.pack_forget()
        if choice == "--max-os-tries":
            self.version_value_entry.configure(placeholder_text="Max OS tries")
            self.version_value_entry.pack(before=self.run_button, pady=(15,5))
        elif choice == "--version-intensity":
            self.version_value_entry.configure(placeholder_text="Intensity (0-9)")
            self.version_value_entry.pack(before=self.run_button, pady=(15,5))

    # Choose -iL file
    def choose_iL_file(self):
        path = filedialog.askopenfilename(title="Select Target List (-iL)")
        if path:
            self.iL_file = path
            self.iL_label.configure(text=f"Loaded: {path}")

    # Run scan
    def start_scan(self):
        target = self.target_entry.get().strip()
        port_choice = self.ports_combo.get()
        ports_value = self.ports_entry.get().strip()
        if port_choice in ["--top-ports", "--exclude-ports"] and ports_value:
            ports_final = f"{port_choice} {ports_value}"
        elif port_choice in ["-p-", "-F"]:
            ports_final = port_choice
        else:
            ports_final = ports_value

        version_option = self.version_menu.get()
        version_value = self.version_value_entry.get().strip()
        if version_option in ["--version-intensity", "--max-os-tries"] and version_value:
            version_final = f"{version_option} {version_value}"
        else:
            version_final = version_option

        selections = {
            "scan": self.scan_menu.get(),
            "host_discovery": self.host_menu.get(),
            "ports": ports_final,
            "version_detection": version_final,
            "timing": self.timing_menu.get(),
            "script": self.script_entry.get(),
            "evasion": self.evasion_menu.get(),
            "iL_file": self.iL_file,
            "random_count": self.random_count_entry.get().strip(),
            "exclude_hosts": self.exclude_entry.get().strip()
        }

        if selections["host_discovery"] in ["-PS", "-PA", "-PU"] and not selections["ports"]:
            messagebox.showerror("Error", f"Ports must be entered for {selections['host_discovery']}.")
            return

        try:
            opts = self.runner.build_options(selections)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return

        command = f"nmap {opts} {target}".strip()
        self.last_command = command

        self.output_box.delete("1.0", "end")
        self.output_box.insert("end", f"$ {command}\n\n")

        threading.Thread(target=self.run_scan_thread, args=(target, opts), daemon=True).start()

    def run_scan_thread(self, target, opts):
        for line in self.runner.run_stream(target, opts):
            self.scan_queue.put(line)

    def poll_queue(self):
        while not self.scan_queue.empty():
            line = self.scan_queue.get()
            self.output_box.insert("end", line)
            self.output_box.see("end")
        self.after(100, self.poll_queue)

    def save_report(self):
        data = self.output_box.get("1.0", "end").strip()
        if not data:
            messagebox.showerror("Error", "No scan results to save")
            return

        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("PDF File", "*.pdf"), ("Text File", "*.txt")])
        if not path:
            return

        if path.endswith(".pdf"):
            self.report.save_pdf(path, data, command=self.last_command)
        else:
            self.report.save_txt(path, data)

        messagebox.showinfo("Saved", "Report saved successfully.")


if __name__ == "__main__":
    app = NmapGUI()
    app.mainloop()
