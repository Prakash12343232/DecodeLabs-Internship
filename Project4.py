import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os
import threading
import time
import math
import winreg
import ctypes

# --- THEME COLORS ---
BG_COLOR = "#0B0F19"
CARD_COLOR = "#161B22"
ACCENT_CYAN = "#00F2FF"
ACCENT_BLUE = "#3D5AFE"
TEXT_PRIMARY = "#FFFFFF"
TEXT_SECONDARY = "#8B949E"
COLOR_LOW = "#00E676"
COLOR_MEDIUM = "#FFD600"
COLOR_HIGH = "#FF9100"
COLOR_CRITICAL = "#FF5252"

class RiskMeter(tk.Canvas):
    """Custom semi-circular gauge for risk assessment."""
    def __init__(self, parent, size=240, **kwargs):
        super().__init__(parent, width=size, height=size//1.5, bg=CARD_COLOR, highlightthickness=0, **kwargs)
        self.size = size
        self.draw_gauge(0)

    def draw_gauge(self, percent):
        self.delete("all")
        padding = 30
        rect = (padding, padding, self.size - padding, self.size - padding)
        
        # Background arc
        self.create_arc(rect, start=0, extent=180, outline="#21262D", width=20, style="arc")
        
        # Color based on percent
        color = COLOR_LOW
        if percent > 25: color = COLOR_MEDIUM
        if percent > 50: color = COLOR_HIGH
        if percent > 75: color = COLOR_CRITICAL
        
        # Foreground arc (Risk level)
        extent = (percent / 100) * 180
        self.create_arc(rect, start=180, extent=-extent, outline=color, width=20, style="arc")
        
        # Center Text
        self.create_text(self.size/2, self.size/2.2, text=f"{percent}%", fill=TEXT_PRIMARY, font=("Arial", 28, "bold"))
        self.create_text(self.size/2, self.size/1.8, text="THREAT LEVEL", fill=TEXT_SECONDARY, font=("Arial", 10, "bold"))

    def set_value(self, value):
        current = 0
        step = 2
        while current <= value:
            self.draw_gauge(current)
            self.update()
            current += step
            time.sleep(0.01)

class ModernButton(tk.Canvas):
    """Custom animated button with hover effects."""
    def __init__(self, parent, text, command=None, width=160, height=45):
        super().__init__(parent, width=width, height=height, bg=BG_COLOR, highlightthickness=0)
        self.command = command
        self.width = width
        self.height = height
        self.rect = self.create_rounded_rect(2, 2, width-2, height-2, 8, fill=ACCENT_BLUE)
        self.text = self.create_text(width/2, height/2, text=text, fill=TEXT_PRIMARY, font=("Arial", 10, "bold"))
        
        self.bind("<Enter>", lambda e: self.itemconfig(self.rect, fill="#536DFE"))
        self.bind("<Leave>", lambda e: self.itemconfig(self.rect, fill=ACCENT_BLUE))
        self.bind("<Button-1>", lambda e: self.command() if self.command else None)

    def create_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [x1+r, y1, x1+r, y1, x2-r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y1+r, x2, y2-r, x2, y2-r, x2, y2, x2-r, y2, x2-r, y2, x1+r, y2, x1+r, y2, x1, y2, x1, y2-r, x1, y2-r, x1, y1+r, x1, y1+r, x1, y1]
        return self.create_polygon(points, **kwargs, smooth=True)

class VulnerabilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("System Vulnerability Checklist | Professional Audit")
        self.root.geometry("1100x750")
        self.root.configure(bg=BG_COLOR)
        
        self.setup_ui()

    def setup_ui(self):
        # Navigation Sidebar
        side_panel = tk.Frame(self.root, bg=CARD_COLOR, width=80)
        side_panel.pack(side="left", fill="y")
        
        # Logo placeholder
        tk.Label(side_panel, text="\u26E8", fg=ACCENT_CYAN, bg=CARD_COLOR, font=("Arial", 32)).pack(pady=40)
        
        # Main Container
        main_frame = tk.Frame(self.root, bg=BG_COLOR)
        main_frame.pack(side="left", fill="both", expand=True, padx=40, pady=30)
        
        # Header Row
        header = tk.Frame(main_frame, bg=BG_COLOR)
        header.pack(fill="x", pady=(0, 30))
        
        title_box = tk.Frame(header, bg=BG_COLOR)
        title_box.pack(side="left")
        tk.Label(title_box, text="System Security Audit", fg=TEXT_PRIMARY, bg=BG_COLOR, font=("Arial", 24, "bold")).pack(anchor="w")
        tk.Label(title_box, text="Vulnerability assessment & risk management console", fg=TEXT_SECONDARY, bg=BG_COLOR, font=("Arial", 10)).pack(anchor="w")
        
        self.btn_analyze = ModernButton(header, "INITIALIZE SCAN", command=self.start_audit)
        self.btn_analyze.pack(side="right")

        # Dashboard Grid
        grid_frame = tk.Frame(main_frame, bg=BG_COLOR)
        grid_frame.pack(fill="both", expand=True)

        # Left Column (Risk & Summary)
        left_col = tk.Frame(grid_frame, bg=BG_COLOR)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Risk Meter Card
        risk_card = tk.Frame(left_col, bg=CARD_COLOR, padx=30, pady=30)
        risk_card.pack(fill="x", pady=(0, 20))
        self.meter = RiskMeter(risk_card)
        self.meter.pack()
        self.risk_label = tk.Label(risk_card, text="SYSTEM STATUS: IDLE", fg=TEXT_SECONDARY, bg=CARD_COLOR, font=("Arial", 12, "bold"))
        self.risk_label.pack(pady=(10, 0))

        # Summary Card
        summary_card = tk.Frame(left_col, bg=CARD_COLOR, padx=25, pady=25)
        summary_card.pack(fill="both", expand=True)
        tk.Label(summary_card, text="EXECUTIVE SUMMARY", fg=ACCENT_CYAN, bg=CARD_COLOR, font=("Arial", 10, "bold")).pack(anchor="w")
        self.summary_text = tk.Label(summary_card, text="Pending system analysis...\nPress 'Initialize Scan' to begin auditing security parameters.", fg=TEXT_SECONDARY, bg=CARD_COLOR, justify="left", wraplength=400, font=("Arial", 10), pady=15)
        self.summary_text.pack(anchor="w")

        # Right Column (Lists)
        right_col = tk.Frame(grid_frame, bg=BG_COLOR)
        right_col.pack(side="left", fill="both", expand=True, padx=(10, 0))

        # Vulnerabilities List
        vuln_frame = tk.Frame(right_col, bg=CARD_COLOR, padx=20, pady=20)
        vuln_frame.pack(fill="both", expand=True, pady=(0, 20))
        tk.Label(vuln_frame, text="CRITICAL VULNERABILITIES", fg=COLOR_CRITICAL, bg=CARD_COLOR, font=("Arial", 10, "bold")).pack(anchor="w")
        
        self.vuln_list = tk.Text(vuln_frame, bg=CARD_COLOR, fg=TEXT_PRIMARY, font=("Consolas", 10), bd=0, highlightthickness=0, pady=10)
        self.vuln_list.pack(fill="both", expand=True)

        # Recommendations List
        rec_frame = tk.Frame(right_col, bg=CARD_COLOR, padx=20, pady=20)
        rec_frame.pack(fill="both", expand=True)
        tk.Label(rec_frame, text="SECURITY RECOMMENDATIONS", fg=COLOR_LOW, bg=CARD_COLOR, font=("Arial", 10, "bold")).pack(anchor="w")
        
        self.rec_list = tk.Text(rec_frame, bg=CARD_COLOR, fg=TEXT_PRIMARY, font=("Arial", 10), bd=0, highlightthickness=0, pady=10)
        self.rec_list.pack(fill="both", expand=True)

    def log_vuln(self, message, severity="High"):
        color = COLOR_CRITICAL if severity == "High" else COLOR_MEDIUM
        tag = f"tag_{severity}"
        self.vuln_list.insert("end", f"[\u26A0] {message}\n", tag)
        self.vuln_list.tag_config(tag, foreground=color)
        self.vuln_list.see("end")

    def log_rec(self, message):
        self.rec_list.insert("end", f"[\u2714] {message}\n")
        self.rec_list.see("end")

    def start_audit(self):
        self.vuln_list.delete("1.0", "end")
        self.rec_list.delete("1.0", "end")
        self.summary_text.config(text="Scanning system configuration...\nExecuting security heuristics...")
        threading.Thread(target=self.run_audit_logic, daemon=True).start()

    def run_audit_logic(self):
        risk_score = 0
        findings = 0
        
        # 1. Firewall Check
        try:
            fw_check = subprocess.check_output("netsh advfirewall show allprofiles state", shell=True).decode()
            if "OFF" in fw_check.upper():
                self.log_vuln("Windows Firewall is disabled in active profiles.", "High")
                self.log_rec("Enable Windows Defender Firewall for all network profiles immediately.")
                risk_score += 30
                findings += 1
        except: pass

        # 2. Admin Privilege Check
        if ctypes.windll.shell32.IsUserAnAdmin() != 0:
            self.log_vuln("User running with full Administrative privileges.", "Medium")
            self.log_rec("Consider using a standard user account for daily activities to mitigate malware impact.")
            risk_score += 15
            findings += 1

        # 3. Guest Account Check
        try:
            guest_check = subprocess.check_output("net user guest", shell=True).decode()
            if "Account active               Yes" in guest_check:
                self.log_vuln("Guest account is enabled (security bypass risk).", "Medium")
                self.log_rec("Disable the Guest account through Computer Management.")
                risk_score += 15
                findings += 1
        except: pass

        # 4. UAC Check
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            uac_val, _ = winreg.QueryValueEx(key, "EnableLUA")
            if uac_val == 0:
                self.log_vuln("User Account Control (UAC) is disabled.", "High")
                self.log_rec("Enable UAC to provide a prompt before applications make changes to your PC.")
                risk_score += 25
                findings += 1
        except: pass

        # 5. Password Policy
        try:
            pwd_policy = subprocess.check_output("net accounts", shell=True).decode()
            if "Minimum password length:         0" in pwd_policy:
                self.log_vuln("No minimum password length policy detected.", "High")
                self.log_rec("Enforce a minimum password length of at least 12 characters via GPO.")
                risk_score += 20
                findings += 1
        except: pass

        # 6. Windows Update Check
        try:
            update_cmd = "powershell (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"
            last_update = subprocess.check_output(update_cmd, shell=True).decode().strip()
            if not last_update:
                self.log_vuln("System update history is missing or corrupted.", "Medium")
                self.log_rec("Run Windows Update to ensure the latest security patches are installed.")
                risk_score += 10
                findings += 1
        except: pass

        self.root.after(0, lambda: self.finalize_ui(risk_score, findings))

    def finalize_ui(self, score, findings):
        score = min(score, 100)
        self.meter.set_value(score)
        
        status = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
        color = COLOR_CRITICAL if score >= 80 else COLOR_HIGH if score >= 60 else COLOR_MEDIUM if score >= 30 else COLOR_LOW
        
        self.risk_label.config(text=f"SYSTEM STATUS: {status}", fg=color)
        summary = f"Audit complete. Detected {findings} security vulnerabilities. The current system threat level is rated as {status}. Review the recommendations panel to improve your security posture."
        self.summary_text.config(text=summary)
        
        if findings == 0:
            self.log_rec("System configuration meets baseline security standards.")
            self.meter.set_value(5)

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityApp(root)
    root.mainloop()
