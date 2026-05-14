import tkinter as tk
from tkinter import ttk, messagebox
import re
from dataclasses import dataclass
from typing import List, Tuple, Dict


# -----------------------------
# Phishing Detection Logic
# -----------------------------

@dataclass
class DetectionResult:
    risk_level: str  # "Safe" | "Suspicious" | "Dangerous"
    risk_score: int
    red_flags: List[str]
    warnings: List[str]
    keywords_found: List[str]
    details: str
    suspicious_domains: List[str]
    suspicious_links: List[str]


def normalize_text(text: str) -> str:
    """Normalize input text for consistent matching."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.lower().strip()


def extract_urls(text: str) -> List[str]:
    """Extract URLs from the input text."""
    # Basic URL extraction: covers http(s) and domain-like strings with TLD
    url_pattern = re.compile(
        r"((https?://)?(www\.)?[a-z0-9-]{1,256}\.[a-z]{2,24}\b([^\s<>()\"']*)?)",
        re.IGNORECASE,
    )
    urls = []
    for match in url_pattern.finditer(text):
        candidate = match.group(1)
        # Avoid grabbing email local parts / too short strings
        if candidate and "." in candidate and len(candidate) >= 8:
            urls.append(candidate)
    # Deduplicate while preserving order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def looks_like_email_phishing_pattern(text: str) -> List[str]:
    """Detect suspicious email patterns (common phishing cues)."""
    patterns = [
        ("password reset", r"\bpassword\s*(reset|change|update)\b"),
        ("account locked", r"\baccount\s*locked\b"),
        ("verify account", r"\b(verify|verification)\b.*\b(account|login)\b"),
        ("limited time", r"\blimited\s*time\b"),
        ("urgent", r"\burgent\b|\bimmediately\b|\bact\s*now\b"),
        ("bank/financial", r"\b(bank|billing|wire|payment|transfer)\b"),
        ("security alert", r"\b(security\s*alert|unusual\s*activity|suspicious\s*login)\b"),
        ("confirm identity", r"\b(confirm|verify)\s*(your\s*)?(identity|credentials|account)\b"),
        ("click to claim", r"\bclick\b.*\b(claim|reward|prize)\b"),
    ]

    found = []
    for label, rx in patterns:
        if re.search(rx, text, flags=re.IGNORECASE):
            found.append(label)
    return found


def detect_keywords(text: str) -> List[str]:
    """Detect phishing keywords and urgency words."""
    keyword_map = {
        # Required urgency words
        "urgent": r"\burgent\b",
        "verify": r"\bverify\b|\bverification\b",
        "password": r"\bpassword\b",
        "bank": r"\bbank\b",
        "limited time": r"\blimited\s*time\b",
        "account locked": r"\baccount\s*locked\b",
        # Additional common phishing keywords
        "account suspended": r"\baccount\s*suspended\b",
        "verify your account": r"\bverify\s+(your\s+)?account\b",
        "suspicious login": r"\bsuspicious\s+login\b|\bunusual\s+activity\b",
        "security alert": r"\bsecurity\s+alert\b",
        "update credentials": r"\bupdate\s+(your\s+)?credentials\b",
        "immediate action": r"\bimmediate\s+action\b|\bact\s*now\b",
        "confirm personal information": r"\bconfirm\b.*\bpersonal\s+information\b",
    }

    found = []
    for label, rx in keyword_map.items():
        if re.search(rx, text, flags=re.IGNORECASE):
            found.append(label)

    # Also detect "URGENT" variants via compact heuristics
    if re.search(r"\bimmediately\b", text, flags=re.IGNORECASE):
        if "urgent" not in found:
            found.append("urgent")
    return found


def extract_domains_from_urls(urls: List[str]) -> List[str]:
    """Extract domains from a list of URLs."""
    domains = []
    for u in urls:
        # Remove protocol if present
        u2 = re.sub(r"^https?://", "", u, flags=re.IGNORECASE)
        u2 = u2.split("/")[0]
        u2 = u2.strip().lower()
        if u2:
            domains.append(u2)
    # Deduplicate
    out = []
    seen = set()
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def is_fake_domain(domain: str) -> bool:
    """
    Heuristics for fake domains:
    - Look for suspicious TLDs (common in phishing)
    - Look for punycode-like patterns
    - Look for multiple hyphens / very long subdomains
    - Look for domain typos or unusual characters (we keep simple)
    """
    d = domain.lower()

    # Punycode indicator
    if "xn--" in d:
        return True

    # Multiple hyphens or long domain label
    parts = d.split(".")
    if len(parts) >= 4:
        # Many subdomains can indicate spoofed routing
        if any(len(p) > 15 for p in parts[:-2]):
            return True
        return True

    # Common suspicious TLD-ish patterns (heuristic, not definitive)
    suspicious_tlds = {"zip", "mov", "tk", "gq", "ml", "cf", "work", "support", "top", "click", "xyz"}
    tld = parts[-1] if parts else ""
    if tld in suspicious_tlds:
        return True

    # Excessive hyphens
    hyphen_count = d.count("-")
    if hyphen_count >= 3:
        return True

    # Suspicious domain keywords
    suspicious_words = ["secure-login", "verify", "account", "update", "billing", "pay", "bank", "support"]
    if any(sw in d.replace(".", "-") for sw in suspicious_words) and hyphen_count >= 1:
        return True

    # IP address as domain (often suspicious)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d):
        return True

    return False


def detect_fake_domains(text: str) -> Tuple[List[str], List[str]]:
    """Detect potential fake domains and suspicious domains list."""
    urls = extract_urls(text)
    domains = extract_domains_from_urls(urls)
    fake = [d for d in domains if is_fake_domain(d)]
    return urls, fake


def detect_suspicious_links(text: str) -> Tuple[List[str], List[str]]:
    """
    Detect suspicious links:
    - URL shorteners
    - Links with lots of tracking params
    - Links requesting credential/payment action
    """
    urls = extract_urls(text)
    suspicious = []

    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "tinyurl", "goo.gl", "is.gd", "ow.ly", "rebrand.ly", "buff.ly"
    }

    for u in urls:
        u_lower = u.lower()

        # URL shorteners
        if any(s in u_lower for s in shorteners):
            suspicious.append(u)
            continue

        # High parameter count
        if "?" in u_lower:
            param_count = u_lower.count("&") + u_lower.count("=")  # rough
            if param_count >= 3:
                suspicious.append(u)
                continue

        # Credential / verification / login in link path
        if re.search(r"/(login|verify|account|password|reset|secure|update|billing)/", u_lower):
            suspicious.append(u)
            continue

    # Extra suspicious link cues without explicit URL:
    # e.g. "click here" followed by "verify password" text
    return urls, suspicious


def detect_suspicious_email_patterns(text: str) -> List[str]:
    """Detect common phishing email patterns."""
    return looks_like_email_phishing_pattern(text)


def score_phishing(result_parts: Dict[str, List[str]]) -> Tuple[str, int, List[str]]:
    """
    Score based on:
    - Urgency words
    - Suspicious domains
    - Suspicious links
    - Suspicious patterns
    - Presence of phishing keywords
    """
    risk_score = 0
    red_flags = []

    urgency_words = result_parts.get("urgency", [])
    keywords = result_parts.get("keywords", [])
    fake_domains = result_parts.get("fake_domains", [])
    suspicious_links = result_parts.get("suspicious_links", [])
    patterns = result_parts.get("patterns", [])

    # Urgency words have higher weight
    urgency_weight = {
        "urgent": 18,
        "verify": 14,
        "password": 18,
        "bank": 16,
        "limited time": 14,
        "account locked": 20,
    }
    for u in urgency_words:
        risk_score += urgency_weight.get(u, 10)
        red_flags.append(f"Urgency/credential cue detected: {u}")

    # Keywords
    for k in keywords:
        risk_score += 6
        # Avoid duplication for urgency that is already flagged
        if k not in urgency_words:
            red_flags.append(f"Phishing keyword detected: {k}")

    # Fake domains
    for d in fake_domains:
        risk_score += 16
        red_flags.append(f"Possible fake domain detected: {d}")

    # Suspicious links
    for link in suspicious_links:
        risk_score += 10
        red_flags.append(f"Suspicious link detected: {link}")

    # Patterns
    for p in patterns:
        risk_score += 7
        red_flags.append(f"Suspicious email pattern detected: {p}")

    # Clamp score
    risk_score = max(0, min(100, risk_score))

    # Determine level
    if risk_score < 25:
        return "Safe", risk_score, red_flags
    if risk_score < 60:
        return "Suspicious", risk_score, red_flags
    return "Dangerous", risk_score, red_flags


def analyze_message(message: str) -> DetectionResult:
    """Main entry point for analyzing a message for phishing signs."""
    text_raw = message or ""
    text = normalize_text(text_raw)

    # Extract components
    urls, fake_domains = detect_fake_domains(text_raw)
    all_urls, suspicious_links = detect_suspicious_links(text_raw)

    keywords = detect_keywords(text_raw)
    urgency = [k for k in keywords if k in {"urgent", "verify", "password", "bank", "limited time", "account locked"}]

    patterns = detect_suspicious_email_patterns(text_raw)

    # Score
    score_parts = {
        "urgency": urgency,
        "keywords": keywords,
        "fake_domains": fake_domains,
        "suspicious_links": suspicious_links,
        "patterns": patterns,
    }
    risk_level, risk_score, red_flags = score_phishing(score_parts)

    # Build warnings & detailed explanation
    warnings = []
    if risk_level == "Safe":
        warnings.append("No strong phishing indicators detected based on heuristic rules.")
    else:
        warnings.append("Multiple phishing indicators were detected. Do not click links or enter credentials.")

    # Human-friendly explanation
    detail_lines = []

    if urgency:
        detail_lines.append("Urgency/Credential cues found: " + ", ".join(sorted(set(urgency))) + ".")
    if keywords:
        detail_lines.append("Phishing keywords detected: " + ", ".join(sorted(set(keywords))) + ".")
    if fake_domains:
        detail_lines.append("Potential fake domains in links: " + ", ".join(sorted(set(fake_domains))) + ".")
    if suspicious_links:
        detail_lines.append("Suspicious links detected (shorteners/parameters/paths): " + ", ".join(sorted(set(suspicious_links))) + ".")
    if patterns:
        detail_lines.append("Suspicious email patterns detected: " + ", ".join(sorted(set(patterns))) + ".")

    if not detail_lines:
        detail_lines.append("No major indicators matched. Still verify the sender and avoid credential sharing.")

    detail_lines.append("")
    detail_lines.append("Safer handling recommendations:")
    detail_lines.append("- Verify the sender domain and message context independently.")
    detail_lines.append("- Hover over links to inspect the real destination domain.")
    detail_lines.append("- Avoid entering passwords or banking details via unexpected messages.")
    detail_lines.append("- If unsure, contact the organization using official support channels.")

    # Include detected keywords (required feature)
    keywords_found = sorted(set(keywords))

    return DetectionResult(
        risk_level=risk_level,
        risk_score=risk_score,
        red_flags=red_flags[:18],
        warnings=warnings,
        keywords_found=keywords_found,
        details="\n".join(detail_lines),
        suspicious_domains=sorted(set(fake_domains)),
        suspicious_links=sorted(set(suspicious_links)),
    )


# -----------------------------
# GUI (Tkinter)
# -----------------------------

class PhishingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Awareness Analyzer")
        self.minsize(980, 650)

        self.configure(bg="#0b0f17")

        # Theme colors
        self.colors = {
            "bg": "#0b0f17",
            "panel": "#111a2b",
            "panel2": "#0f1626",
            "text": "#e6f0ff",
            "muted": "#9fb2d6",
            "border": "#223355",
            "accent": "#4cc9f0",   # cyber cyan
            "accent2": "#8b5cf6",  # purple
            "green": "#22c55e",
            "yellow": "#f59e0b",
            "red": "#ef4444",
            "danger_bg": "#2a0f16",
            "warning_bg": "#241a10",
            "safe_bg": "#0f1f16",
            "shadow": "#000000",
        }

        self._build_ui()

    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=self.colors["bg"])
        header.pack(fill="x", padx=18, pady=(16, 10))

        title = tk.Label(
            header,
            text="Phishing Awareness Analyzer",
            bg=self.colors["bg"],
            fg=self.colors["text"],
            font=("Segoe UI", 18, "bold"),
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            header,
            text="Analyze emails/messages to detect suspicious phishing signals using heuristic rules.",
            bg=self.colors["bg"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
        )
        subtitle.pack(anchor="w", pady=(4, 0))

        # Main layout
        main = tk.Frame(self, bg=self.colors["bg"])
        main.pack(fill="both", expand=True, padx=18, pady=(6, 18))

        left = tk.Frame(main, bg=self.colors["bg"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 14))

        right = tk.Frame(main, bg=self.colors["bg"])
        right.pack(side="right", fill="both", expand=False)

        # Input panel
        input_panel = tk.LabelFrame(
            left,
            text="Message Analyzer",
            bg=self.colors["panel2"],
            fg=self.colors["text"],
            bd=1,
            highlightbackground=self.colors["border"],
            highlightthickness=1,
            font=("Segoe UI", 12, "bold"),
        )
        input_panel.pack(fill="x", pady=(0, 12))

        # Text input
        self.input_text = tk.Text(
            input_panel,
            height=12,
            wrap="word",
            bg="#0d1423",
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            bd=0,
            relief="flat",
            padx=10,
            pady=10,
            font=("Consolas", 11),
        )
        self.input_text.pack(fill="both", expand=True, padx=10, pady=(8, 8))

        # Buttons row
        btn_row = tk.Frame(input_panel, bg=self.colors["panel2"])
        btn_row.pack(fill="x", padx=10, pady=(0, 10))

        self.sample_var = tk.StringVar(value="Sample: Password Reset (Dangerous)")

        samples = [
            "Sample: Password Reset (Dangerous)",
            "Sample: Bank Verification (Dangerous)",
            "Sample: Limited Time Offer (Suspicious)",
            "Sample: Package Delivery Update (Suspicious)",
            "Sample: Security Notice (Safe-ish)",
        ]
        self.sample_combo = ttk.Combobox(
            btn_row,
            values=samples,
            textvariable=self.sample_var,
            state="readonly",
            width=36,
        )
        self.sample_combo.pack(side="left")

        ttk.Style().configure("Cyber.TButton", font=("Segoe UI", 10, "bold"))

        self.analyze_btn = tk.Button(
            btn_row,
            text="Analyze",
            bg=self.colors["accent"],
            fg="#07101a",
            activebackground="#3ab8d8",
            activeforeground="#07101a",
            relief="flat",
            padx=14,
            pady=8,
            font=("Segoe UI", 11, "bold"),
            command=self.on_analyze,
        )
        self.analyze_btn.pack(side="left", padx=10)

        self.clear_btn = tk.Button(
            btn_row,
            text="Clear",
            bg="#1f2a44",
            fg=self.colors["text"],
            activebackground="#263354",
            relief="flat",
            padx=14,
            pady=8,
            font=("Segoe UI", 11, "bold"),
            command=self.on_clear,
        )
        self.clear_btn.pack(side="left")

        self._apply_hover(self.analyze_btn, hover_bg="#3ab8d8")
        self._apply_hover(self.clear_btn, hover_bg="#263354")

        # Results panel
        result_panel = tk.LabelFrame(
            left,
            text="Results",
            bg=self.colors["panel2"],
            fg=self.colors["text"],
            bd=1,
            highlightbackground=self.colors["border"],
            highlightthickness=1,
            font=("Segoe UI", 12, "bold"),
        )
        result_panel.pack(fill="both", expand=True)

        # Risk meter / progress
        meter_frame = tk.Frame(result_panel, bg=self.colors["panel2"])
        meter_frame.pack(fill="x", padx=10, pady=(10, 8))

        self.risk_label = tk.Label(
            meter_frame,
            text="Risk Level: -",
            bg=self.colors["panel2"],
            fg=self.colors["muted"],
            font=("Segoe UI", 12, "bold"),
        )
        self.risk_label.pack(anchor="w")

        bar_bg = "#0a1220"
        self.risk_progress = ttk.Progressbar(
            meter_frame,
            orient="horizontal",
            length=460,
            mode="determinate",
            maximum=100,
        )
        self.risk_progress.pack(fill="x", pady=(6, 0))

        # customize progress bar colors
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "custom.Horizontal.TProgressbar",
            background=self.colors["accent"],
            troughcolor=bar_bg,
            bordercolor=self.colors["border"],
            lightcolor=self.colors["border"],
            darkcolor=self.colors["border"],
            thickness=12,
        )
        self.risk_progress.configure(style="custom.Horizontal.TProgressbar")

        # Warnings / red flags
        self.result_text = tk.Text(
            result_panel,
            height=10,
            wrap="word",
            bg="#0d1423",
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            bd=0,
            relief="flat",
            padx=10,
            pady=10,
            font=("Consolas", 10),
        )
        self.result_text.pack(fill="both", expand=True, padx=10, pady=(10, 10))

        # Make it read-only-ish
        self.result_text.configure(state="disabled")

        # Right panel: details + keywords + red flags
        detail_panel = tk.LabelFrame(
            right,
            text="Security Warnings",
            bg=self.colors["panel2"],
            fg=self.colors["text"],
            bd=1,
            highlightbackground=self.colors["border"],
            highlightthickness=1,
            font=("Segoe UI", 12, "bold"),
        )
        detail_panel.pack(fill="both", expand=True)

        # Keywords list
        kw_title = tk.Label(
            detail_panel,
            text="Detected Keywords / Cues",
            bg=self.colors["panel2"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10, "bold"),
        )
        kw_title.pack(anchor="w", padx=10, pady=(10, 0))

        self.keywords_list = tk.Listbox(
            detail_panel,
            bg="#0d1423",
            fg=self.colors["text"],
            selectbackground="#203052",
            selectforeground=self.colors["text"],
            height=8,
            bd=0,
            relief="flat",
            font=("Consolas", 10),
        )
        self.keywords_list.pack(fill="x", padx=10, pady=(6, 10))

        # Domains and link warnings (summary)
        self.meta_summary = tk.Label(
            detail_panel,
            text="",
            bg=self.colors["panel2"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
            justify="left",
            wraplength=320,
        )
        self.meta_summary.pack(anchor="w", padx=10, pady=(0, 10))

        # Detailed explanation
        details_title = tk.Label(
            detail_panel,
            text="Why this message is unsafe (explanation)",
            bg=self.colors["panel2"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10, "bold"),
        )
        details_title.pack(anchor="w", padx=10, pady=(0, 6))

        self.details_text = tk.Text(
            detail_panel,
            height=12,
            wrap="word",
            bg="#0d1423",
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            bd=0,
            relief="flat",
            padx=10,
            pady=10,
            font=("Consolas", 10),
        )
        self.details_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.details_text.configure(state="disabled")

        # Footer tips
        footer = tk.Frame(self, bg=self.colors["bg"])
        footer.pack(fill="x", padx=18, pady=(0, 10))

        tip = tk.Label(
            footer,
            text="Tip: Never enter passwords via unexpected links. Verify using official websites or support channels.",
            bg=self.colors["bg"],
            fg="#7fa0d2",
            font=("Segoe UI", 9, "italic"),
        )
        tip.pack(anchor="w")

        # Initial sample text
        self.load_sample_by_name(self.sample_var.get())

    def _apply_hover(self, widget: tk.Widget, hover_bg: str):
        """Add simple hover effects to Tkinter button-like widgets."""
        def on_enter(_):
            try:
                widget.configure(bg=hover_bg)
            except tk.TclError:
                pass

        def on_leave(_):
            # restore original color if possible
            try:
                # For buttons we use "bg" in creation; store it if exists
                orig = getattr(widget, "_orig_bg", None)
                if orig:
                    widget.configure(bg=orig)
                else:
                    # fallback: no-op
                    pass
            except tk.TclError:
                pass

        # store original background
        try:
            widget._orig_bg = widget.cget("bg")
        except tk.TclError:
            widget._orig_bg = None

        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def set_readonly_text(self, widget: tk.Text, content: str):
        widget.configure(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, content)
        widget.configure(state="disabled")

    def on_clear(self):
        self.input_text.delete("1.0", tk.END)
        self.risk_progress["value"] = 0
        self.risk_label.configure(text="Risk Level: -", fg=self.colors["muted"])
        self.risk_progress.configure(style="custom.Horizontal.TProgressbar")
        self.set_readonly_text(self.result_text, "")
        self.set_readonly_text(self.details_text, "")
        self.keywords_list.delete(0, tk.END)
        self.meta_summary.configure(text="")

    def on_analyze(self):
        message = self.input_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Input Required", "Paste or type an email/message to analyze.")
            return

        result = analyze_message(message)

        # Risk UI updates
        if result.risk_level == "Safe":
            color = self.colors["green"]
            meter_bg = self.colors["safe_bg"]
        elif result.risk_level == "Suspicious":
            color = self.colors["yellow"]
            meter_bg = self.colors["warning_bg"]
        else:
            color = self.colors["red"]
            meter_bg = self.colors["danger_bg"]

        # Update progress style color
        style = ttk.Style()
        style.configure(
            "custom.Horizontal.TProgressbar",
            background=color,
            troughcolor="#0a1220",
            bordercolor=self.colors["border"],
            lightcolor=self.colors["border"],
            darkcolor=self.colors["border"],
            thickness=12,
        )

        self.risk_progress["value"] = result.risk_score
        self.risk_label.configure(
            text=f"Risk Level: {result.risk_level}  ({result.risk_score}/100)",
            fg=color,
        )

        # Result section text
        if result.red_flags:
            flags = "\n".join(f"- {f}" for f in result.red_flags)
        else:
            flags = "- No notable red flags found."

        summary = "\n".join(result.warnings) + "\n\nRed Flags:\n" + flags

        self.set_readonly_text(self.result_text, summary)

        # Keywords list
        self.keywords_list.delete(0, tk.END)
        if result.keywords_found:
            for k in result.keywords_found:
                self.keywords_list.insert(tk.END, k)
        else:
            self.keywords_list.insert(tk.END, "None detected")

        # Meta summary (fake domains / suspicious links)
        meta_lines = []
        if result.suspicious_domains:
            meta_lines.append(f"Fake domains detected: {', '.join(result.suspicious_domains[:4])}" + ("..." if len(result.suspicious_domains) > 4 else ""))
        if result.suspicious_links:
            meta_lines.append(f"Suspicious links detected: {', '.join(result.suspicious_links[:3])}" + ("..." if len(result.suspicious_links) > 3 else ""))

        if not meta_lines:
            meta_lines.append("No link/domain anomalies detected by heuristics.")

        self.meta_summary.configure(text="\n".join(meta_lines))

        # Detailed explanation
        self.set_readonly_text(self.details_text, result.details)

        # Tiny attention animation for risky results (simple flash)
        self._animate_risk(color, result.risk_level)

    def _animate_risk(self, color: str, level: str):
        """Small, lightweight UI animation on risk update."""
        # Flash the risk label foreground quickly (2-3 cycles)
        original = self.risk_label.cget("fg")

        steps = 6
        delay = 60

        def pulse(i=0):
            if i >= steps:
                self.risk_label.configure(fg=color)
                return
            # Alternate between muted and accent/risk color
            fg = color if i % 2 == 0 else self.colors["muted"]
            self.risk_label.configure(fg=fg)
            self.after(delay, lambda: pulse(i + 1))

        if level in {"Suspicious", "Dangerous"}:
            pulse(0)
        else:
            self.risk_label.configure(fg=self.colors["green"])

    def sample_messages(self) -> Dict[str, str]:
        """Provide sample phishing and non-phishing messages for testing."""
        return {
            "Sample: Password Reset (Dangerous)": (
                "Subject: Action Required - Password Reset\n\n"
                "Hi,\n\n"
                "We noticed unusual activity on your account. Please verify your identity and reset your password immediately.\n"
                "Account locked due to suspicious login attempts.\n"
                "Click here to verify: https://secure-login-account-verification.xyz/login?token=AbC123&user=demo\n\n"
                "Thanks,\n"
                "Security Team"
            ),
            "Sample: Bank Verification (Dangerous)": (
                "Dear Customer,\n\n"
                "URGENT: Your bank account requires verification to prevent service interruption.\n"
                "Limited time offer to confirm your details.\n\n"
                "Verify now: http://bit.ly/confirm-bank-account-2025\n\n"
                "Failure to verify will result in account suspension.\n"
                "Regards,\n"
                "Bank Support"
            ),
            "Sample: Limited Time Offer (Suspicious)": (
                "Hello,\n\n"
                "Limited time to claim your reward! We detected a problem with your billing.\n"
                "Verify your account within 24 hours.\n"
                "Visit: https://example-service.com/update-account?ref=promo&campaign=summer&x=1&y=2\n\n"
                "Thank you."
            ),
            "Sample: Package Delivery Update (Suspicious)": (
                "Notice: Delivery Update\n\n"
                "Your package could not be delivered. To re-route, verify your address.\n"
                "Act now before we cancel the shipment.\n"
                "Tracking: https://t.co/track-package-98211?src=email&ad=1\n"
                "Do not ignore this message.\n"
            ),
            "Sample: Security Notice (Safe-ish)": (
                "Hi there,\n\n"
                "This is a reminder to review your account security settings.\n"
                "No action is required if you recognize this activity.\n"
                "For assistance, visit the official website by typing it into your browser.\n\n"
                "Best regards."
            ),
        }

    def load_sample_by_name(self, name: str):
        """Load a chosen sample into the input text area."""
        samples = self.sample_messages()
        content = samples.get(name, "")
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert(tk.END, content)

    def on_sample_selected(self, _event=None):
        self.load_sample_by_name(self.sample_var.get())


def main():
    app = PhishingApp()
    # Map combobox selection changes to sample loader
    app.sample_combo.bind("<<ComboboxSelected>>", app.on_sample_selected)
    app.mainloop()


if __name__ == "__main__":
    main()
