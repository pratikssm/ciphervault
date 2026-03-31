import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import bcrypt
import time
import re
import random
import string
import math
from datetime import datetime

# ============================================================
#                    DATABASE SETUP  (auto-migrate safe)
# ============================================================
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Create base table (works even if DB already exists with old schema)
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password        BLOB NOT NULL,
    security_answer TEXT NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT,
    status    TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()

# ---- AUTO-MIGRATE: safely add new columns to existing DB ----
def _col_exists(table, col):
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == col for row in cursor.fetchall())

_migrations = [
    ("users", "email",
     "ALTER TABLE users ADD COLUMN email TEXT"),
    ("users", "security_question",
     "ALTER TABLE users ADD COLUMN security_question TEXT DEFAULT 'What was the name of your first pet?'"),
    ("users", "created_at",
     "ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP"),
    ("users", "last_login",
     "ALTER TABLE users ADD COLUMN last_login TEXT"),
    ("users", "login_count",
     "ALTER TABLE users ADD COLUMN login_count INTEGER DEFAULT 0"),
]

for _table, _col, _sql in _migrations:
    if not _col_exists(_table, _col):
        cursor.execute(_sql)

conn.commit()

# ============================================================
#                  SECURITY VARIABLES
# ============================================================
failed_attempts = {}
lockout_time    = {}
MAX_ATTEMPTS    = 3
LOCK_TIME       = 60

SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What is your mother's maiden name?",
    "What city were you born in?",
    "What was the name of your elementary school?",
    "What is your favorite movie?",
]

# ============================================================
#                    THEME
# ============================================================
C = {
    "bg":     "#0a0a0f",
    "card":   "#12121a",
    "inp":    "#1a1a28",
    "cyan":   "#00f5ff",
    "purple": "#7b2fff",
    "pink":   "#ff2f7b",
    "green":  "#00ff88",
    "yellow": "#ffcc00",
    "red":    "#ff4444",
    "fg":     "#e8e8ff",
    "dim":    "#6666aa",
    "border": "#2a2a40",
}

F = {
    "big":  ("Courier New", 20, "bold"),
    "mid":  ("Courier New", 10, "bold"),
    "lbl":  ("Courier New", 9,  "bold"),
    "inp":  ("Courier New", 11),
    "btn":  ("Courier New", 10, "bold"),
    "sm":   ("Courier New", 8),
    "mono": ("Courier New", 10),
}

# ============================================================
#                   HELPERS
# ============================================================
def log_activity(message, username="system", status="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("activity_log.txt", "a") as f:
        f.write(f"[{ts}] [{status}] [{username}] {message}\n")
    try:
        cursor.execute(
            "INSERT INTO login_history (username, status) VALUES (?, ?)",
            (username, status)
        )
        conn.commit()
    except Exception:
        pass

def check_strength(password):
    score = 0
    checks = [
        (len(password) >= 8,  1),
        (len(password) >= 12, 1),
        (bool(re.search(r"[A-Z]", password)), 1),
        (bool(re.search(r"[a-z]", password)), 1),
        (bool(re.search(r"[0-9]", password)), 1),
        (bool(re.search(r"[@$!%*?&#^_\-+=]", password)), 2),
        (len(set(password)) > 6, 1),
    ]
    for passed, pts in checks:
        if passed:
            score += pts
    if score <= 2:   return score, "WEAK",   C["red"]
    elif score <= 4: return score, "FAIR",   C["yellow"]
    elif score <= 6: return score, "GOOD",   C["cyan"]
    else:            return score, "STRONG", C["green"]

def gen_password():
    chars = string.ascii_letters + string.digits + "@$!%*?&#"
    pwd = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice("@$!%*?&#"),
    ] + [random.choice(chars) for _ in range(8)]
    random.shuffle(pwd)
    return "".join(pwd)

# ============================================================
#                  WIDGET HELPERS
# ============================================================
def make_entry(parent, show=""):
    outer = tk.Frame(parent, bg=C["inp"],
                     highlightbackground=C["border"],
                     highlightthickness=1)
    entry = tk.Entry(outer, font=F["inp"], bg=C["inp"], fg=C["fg"],
                     insertbackground=C["cyan"], relief="flat",
                     bd=6, show=show)
    entry.pack(fill="x", expand=True, side="left")
    entry.bind("<FocusIn>",  lambda e: outer.config(highlightbackground=C["cyan"]))
    entry.bind("<FocusOut>", lambda e: outer.config(highlightbackground=C["border"]))
    return outer, entry

def make_label(parent, text):
    tk.Label(parent, text=text, font=F["lbl"],
             bg=C["card"], fg=C["dim"], anchor="w").pack(fill="x", pady=(8, 1))

def make_btn(parent, text, cmd, bg=None, fg=None):
    bg = bg or C["cyan"]
    fg = fg or C["bg"]
    btn = tk.Label(parent, text=text, font=F["btn"],
                   bg=bg, fg=fg, cursor="hand2", pady=9)
    btn.pack(fill="x", pady=3)
    orig_bg = bg
    btn.bind("<Button-1>", lambda e: cmd())
    btn.bind("<Enter>",    lambda e: btn.config(bg=C["purple"], fg="white"))
    btn.bind("<Leave>",    lambda e: btn.config(bg=orig_bg, fg=fg))
    return btn

# ============================================================
#                  MAIN APPLICATION
# ============================================================
class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CipherVault — Secure Login System")
        self.root.geometry("500x700")
        self.root.resizable(False, False)
        self.root.configure(bg=C["bg"])

        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"500x700+{(sw-500)//2}+{(sh-700)//2}")

        self.anim_on = True
        self.mode = "login"
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._quit)
        self._pulse()
        self.root.mainloop()

    def _quit(self):
        self.anim_on = False
        try:
            conn.close()
        except Exception:
            pass
        self.root.destroy()

    # ── HEADER ──────────────────────────────────────────────
    def _build(self):
        self.hdr = tk.Canvas(self.root, width=500, height=100,
                             bg=C["bg"], highlightthickness=0)
        self.hdr.pack(fill="x")
        self._draw_header()

        # Tab bar
        tab_bar = tk.Frame(self.root, bg=C["bg"])
        tab_bar.pack(fill="x")
        self.tab_btns = {}
        for label, mode in [("  LOGIN  ", "login"),
                             ("REGISTER ", "register"),
                             ("  RESET  ", "reset")]:
            f = tk.Frame(tab_bar, bg=C["bg"])
            f.pack(side="left", expand=True, fill="x")
            b = tk.Label(f, text=label, font=F["mid"],
                         bg=C["bg"], fg=C["dim"], cursor="hand2", pady=7)
            b.pack(fill="x")
            b.bind("<Button-1>", lambda e, m=mode: self._switch(m))
            ind = tk.Frame(f, bg=C["bg"], height=2)
            ind.pack(fill="x")
            self.tab_btns[mode] = (b, ind)

        # Content frame (fixed parent for all panels)
        self.content = tk.Frame(self.root, bg=C["card"])
        self.content.pack(fill="both", expand=True, padx=12, pady=6)

        # Status bar
        self.status_var = tk.StringVar(value="System ready  |  CipherVault v2.0")
        tk.Frame(self.root, bg=C["cyan"], height=1).pack(fill="x")
        tk.Label(self.root, textvariable=self.status_var,
                 font=F["sm"], bg="#0d0d18", fg=C["dim"],
                 anchor="w", padx=8).pack(fill="x")

        # Build panels INSIDE self.content
        self._build_login_panel()
        self._build_register_panel()
        self._build_reset_panel()

        self._switch("login")

    def _draw_header(self):
        c = self.hdr
        c.delete("all")
        for i in range(100):
            r = max(0, min(255, 10 + i // 6))
            b = max(0, min(255, 20 + i // 3))
            c.create_rectangle(0, i, 500, i + 1,
                                fill=f"#{r:02x}0a{b:02x}", outline="")
        for x in range(0, 500, 40):
            c.create_line(x, 0, x, 100, fill="#2a2a3a", width=1)
        for y in range(0, 100, 20):
            c.create_line(0, y, 500, y, fill="#2a2a3a", width=1)
        c.create_oval(10, -10, 110, 80, fill="#0a2a2a", outline="")
        c.create_oval(390, 20, 510, 110, fill="#1a0a2a", outline="")
        self.hdr_title = c.create_text(250, 38, text="CIPHER VAULT",
                                        font=("Courier New", 24, "bold"),
                                        fill=C["cyan"])
        c.create_text(250, 62,
                      text="ADVANCED SECURE LOGIN SYSTEM v2.0",
                      font=F["sm"], fill=C["dim"])
        c.create_line(50, 78, 450, 78, fill=C["cyan"], width=1)
        c.create_oval(44, 74, 56, 84, fill=C["cyan"], outline="")
        c.create_oval(444, 74, 456, 84, fill=C["purple"], outline="")

    # ── PANELS ──────────────────────────────────────────────
    def _build_login_panel(self):
        p = tk.Frame(self.content, bg=C["card"])
        self.panel_login = p

        make_label(p, "  USERNAME")
        self._lf_user_outer, self._lf_user = make_entry(p)
        self._lf_user_outer.pack(fill="x")

        make_label(p, "  PASSWORD")
        pw_row = tk.Frame(p, bg=C["inp"],
                          highlightbackground=C["border"], highlightthickness=1)
        pw_row.pack(fill="x")
        self._lf_pw = tk.Entry(pw_row, font=F["inp"], bg=C["inp"], fg=C["fg"],
                               insertbackground=C["cyan"], relief="flat", bd=6, show="●")
        self._lf_pw.pack(side="left", fill="x", expand=True)
        self._lf_pw.bind("<FocusIn>",
                         lambda e: pw_row.config(highlightbackground=C["cyan"]))
        self._lf_pw.bind("<FocusOut>",
                         lambda e: pw_row.config(highlightbackground=C["border"]))
        self._lf_eye_on = False
        eye = tk.Label(pw_row, text="👁", font=("Arial", 11),
                       bg=C["inp"], fg=C["dim"], cursor="hand2", padx=6)
        eye.pack(side="right")
        eye.bind("<Button-1>",
                 lambda e: self._toggle_eye(self._lf_pw, eye, "_lf_eye_on"))

        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", pady=12)
        make_btn(p, "   LOGIN", self._login)
        make_btn(p, "   CLEAR", self._clear_login, bg=C["inp"], fg=C["dim"])
        tk.Label(p, text="Enter credentials to access your account.",
                 font=F["sm"], bg=C["card"], fg=C["dim"],
                 anchor="w").pack(fill="x", pady=6)

    def _build_register_panel(self):
        p = tk.Frame(self.content, bg=C["card"])
        self.panel_register = p

        make_label(p, "  USERNAME")
        self._rf_user_outer, self._rf_user = make_entry(p)
        self._rf_user_outer.pack(fill="x")

        make_label(p, "  EMAIL ADDRESS  (optional)")
        self._rf_email_outer, self._rf_email = make_entry(p)
        self._rf_email_outer.pack(fill="x")

        make_label(p, "  PASSWORD")
        pw_row = tk.Frame(p, bg=C["inp"],
                          highlightbackground=C["border"], highlightthickness=1)
        pw_row.pack(fill="x")
        self._rf_pw = tk.Entry(pw_row, font=F["inp"], bg=C["inp"], fg=C["fg"],
                               insertbackground=C["cyan"], relief="flat", bd=6, show="●")
        self._rf_pw.pack(side="left", fill="x", expand=True)
        self._rf_pw.bind("<FocusIn>",
                         lambda e: pw_row.config(highlightbackground=C["cyan"]))
        self._rf_pw.bind("<FocusOut>",
                         lambda e: pw_row.config(highlightbackground=C["border"]))
        self._rf_pw.bind("<KeyRelease>", self._update_strength_rf)
        self._rf_eye_on = False
        eye_r = tk.Label(pw_row, text="👁", font=("Arial", 11),
                         bg=C["inp"], fg=C["dim"], cursor="hand2", padx=6)
        eye_r.pack(side="right")
        eye_r.bind("<Button-1>",
                   lambda e: self._toggle_eye(self._rf_pw, eye_r, "_rf_eye_on",
                                              extra=self._rf_conf))
        gen = tk.Label(pw_row, text="⚙", font=("Arial", 12),
                       bg=C["inp"], fg=C["purple"], cursor="hand2", padx=6)
        gen.pack(side="right")
        gen.bind("<Button-1>", lambda e: self._gen_pw())

        # Strength bar
        self._rf_str_lbl = tk.Label(p, text="", font=F["sm"],
                                    bg=C["card"], fg=C["dim"], anchor="w")
        self._rf_str_lbl.pack(fill="x", pady=(2, 0))
        self._rf_str_cv = tk.Canvas(p, height=4, bg=C["inp"], highlightthickness=0)
        self._rf_str_cv.pack(fill="x")

        make_label(p, "  CONFIRM PASSWORD")
        conf_row = tk.Frame(p, bg=C["inp"],
                            highlightbackground=C["border"], highlightthickness=1)
        conf_row.pack(fill="x")
        self._rf_conf = tk.Entry(conf_row, font=F["inp"], bg=C["inp"], fg=C["fg"],
                                 insertbackground=C["cyan"], relief="flat", bd=6, show="●")
        self._rf_conf.pack(fill="x", expand=True)
        self._rf_conf.bind("<FocusIn>",
                           lambda e: conf_row.config(highlightbackground=C["cyan"]))
        self._rf_conf.bind("<FocusOut>",
                           lambda e: conf_row.config(highlightbackground=C["border"]))

        make_label(p, "  SECURITY QUESTION")
        self._rf_sq_var = tk.StringVar(value=SECURITY_QUESTIONS[0])
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("CV.TCombobox",
                        fieldbackground=C["inp"], background=C["inp"],
                        foreground=C["fg"], selectbackground=C["purple"],
                        bordercolor=C["border"], arrowcolor=C["cyan"])
        ttk.Combobox(p, textvariable=self._rf_sq_var,
                     values=SECURITY_QUESTIONS, state="readonly",
                     style="CV.TCombobox", font=F["sm"]).pack(fill="x")

        make_label(p, "  SECURITY ANSWER")
        self._rf_ans_outer, self._rf_ans = make_entry(p)
        self._rf_ans_outer.pack(fill="x")

        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", pady=8)
        make_btn(p, "   CREATE ACCOUNT", self._register)
        make_btn(p, "   CLEAR", self._clear_register, bg=C["inp"], fg=C["dim"])

    def _build_reset_panel(self):
        p = tk.Frame(self.content, bg=C["card"])
        self.panel_reset = p

        make_label(p, "  USERNAME")
        self._rs_user_outer, self._rs_user = make_entry(p)
        self._rs_user_outer.pack(fill="x")

        make_label(p, "  SECURITY ANSWER")
        self._rs_ans_outer, self._rs_ans = make_entry(p)
        self._rs_ans_outer.pack(fill="x")

        make_label(p, "  NEW PASSWORD")
        pw_row = tk.Frame(p, bg=C["inp"],
                          highlightbackground=C["border"], highlightthickness=1)
        pw_row.pack(fill="x")
        self._rs_pw = tk.Entry(pw_row, font=F["inp"], bg=C["inp"], fg=C["fg"],
                               insertbackground=C["cyan"], relief="flat", bd=6, show="●")
        self._rs_pw.pack(side="left", fill="x", expand=True)
        self._rs_pw.bind("<FocusIn>",
                         lambda e: pw_row.config(highlightbackground=C["cyan"]))
        self._rs_pw.bind("<FocusOut>",
                         lambda e: pw_row.config(highlightbackground=C["border"]))
        self._rs_pw.bind("<KeyRelease>", self._update_strength_rs)
        self._rs_eye_on = False
        eye_s = tk.Label(pw_row, text="👁", font=("Arial", 11),
                         bg=C["inp"], fg=C["dim"], cursor="hand2", padx=6)
        eye_s.pack(side="right")
        eye_s.bind("<Button-1>",
                   lambda e: self._toggle_eye(self._rs_pw, eye_s, "_rs_eye_on",
                                              extra=self._rs_conf))

        self._rs_str_lbl = tk.Label(p, text="", font=F["sm"],
                                    bg=C["card"], fg=C["dim"], anchor="w")
        self._rs_str_lbl.pack(fill="x", pady=(2, 0))
        self._rs_str_cv = tk.Canvas(p, height=4, bg=C["inp"], highlightthickness=0)
        self._rs_str_cv.pack(fill="x")

        make_label(p, "  CONFIRM NEW PASSWORD")
        conf_row = tk.Frame(p, bg=C["inp"],
                            highlightbackground=C["border"], highlightthickness=1)
        conf_row.pack(fill="x")
        self._rs_conf = tk.Entry(conf_row, font=F["inp"], bg=C["inp"], fg=C["fg"],
                                 insertbackground=C["cyan"], relief="flat", bd=6, show="●")
        self._rs_conf.pack(fill="x", expand=True)
        self._rs_conf.bind("<FocusIn>",
                           lambda e: conf_row.config(highlightbackground=C["cyan"]))
        self._rs_conf.bind("<FocusOut>",
                           lambda e: conf_row.config(highlightbackground=C["border"]))

        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", pady=8)
        make_btn(p, "   RESET PASSWORD", self._reset)
        make_btn(p, "   CLEAR", self._clear_reset, bg=C["inp"], fg=C["dim"])
        tk.Label(p,
                 text="Provide username, security answer, and new password.",
                 font=F["sm"], bg=C["card"], fg=C["dim"],
                 anchor="w").pack(fill="x", pady=4)

    # ── TAB SWITCHING (clean: pack_forget + pack) ────────────
    def _switch(self, mode):
        self.mode = mode
        for panel in (self.panel_login, self.panel_register, self.panel_reset):
            panel.pack_forget()

        {
            "login":    self.panel_login,
            "register": self.panel_register,
            "reset":    self.panel_reset,
        }[mode].pack(fill="both", expand=True, padx=10, pady=8)

        for m, (btn, ind) in self.tab_btns.items():
            if m == mode:
                btn.config(fg=C["cyan"])
                ind.config(bg=C["cyan"])
            else:
                btn.config(fg=C["dim"])
                ind.config(bg=C["bg"])

        self.status_var.set(f"Mode: {mode.upper()}  |  CipherVault v2.0")

    # ── PASSWORD HELPERS ─────────────────────────────────────
    def _toggle_eye(self, entry, lbl, attr, extra=None):
        state = not getattr(self, attr)
        setattr(self, attr, state)
        ch = "" if state else "●"
        entry.config(show=ch)
        if extra:
            extra.config(show=ch)
        lbl.config(fg=C["cyan"] if state else C["dim"])

    def _gen_pw(self):
        pwd = gen_password()
        self._rf_pw.delete(0, tk.END)
        self._rf_pw.insert(0, pwd)
        self._rf_pw.config(fg=C["green"])
        self._update_strength_rf(None)
        self.status_var.set("Password generated — save it safely!")

    def _update_strength_rf(self, _):
        pwd = self._rf_pw.get()
        if not pwd:
            self._rf_str_lbl.config(text="")
            self._rf_str_cv.delete("all")
            return
        score, level, color = check_strength(pwd)
        self._rf_str_lbl.config(text=f"Strength: {level}", fg=color)
        self._rf_str_cv.update_idletasks()
        w = self._rf_str_cv.winfo_width() or 460
        bar = int((min(score, 7) / 7) * w)
        self._rf_str_cv.delete("all")
        self._rf_str_cv.create_rectangle(0, 0, bar, 4, fill=color, outline="")

    def _update_strength_rs(self, _):
        pwd = self._rs_pw.get()
        if not pwd:
            self._rs_str_lbl.config(text="")
            self._rs_str_cv.delete("all")
            return
        score, level, color = check_strength(pwd)
        self._rs_str_lbl.config(text=f"Strength: {level}", fg=color)
        self._rs_str_cv.update_idletasks()
        w = self._rs_str_cv.winfo_width() or 460
        bar = int((min(score, 7) / 7) * w)
        self._rs_str_cv.delete("all")
        self._rs_str_cv.create_rectangle(0, 0, bar, 4, fill=color, outline="")

    # ── CLEAR ────────────────────────────────────────────────
    def _clear_login(self):
        self._lf_user.delete(0, tk.END)
        self._lf_pw.delete(0, tk.END)

    def _clear_register(self):
        for e in (self._rf_user, self._rf_email,
                  self._rf_pw, self._rf_conf, self._rf_ans):
            e.delete(0, tk.END)
        self._rf_str_lbl.config(text="")
        self._rf_str_cv.delete("all")

    def _clear_reset(self):
        for e in (self._rs_user, self._rs_ans, self._rs_pw, self._rs_conf):
            e.delete(0, tk.END)
        self._rs_str_lbl.config(text="")
        self._rs_str_cv.delete("all")

    # ── SHAKE ────────────────────────────────────────────────
    def _shake(self):
        x0, y0 = self.root.winfo_x(), self.root.winfo_y()
        offs = [12, -12, 9, -9, 6, -6, 3, -3, 0]
        def step(i=0):
            if i < len(offs):
                self.root.geometry(f"+{x0+offs[i]}+{y0}")
                self.root.after(35, step, i + 1)
            else:
                self.root.geometry(f"+{x0}+{y0}")
        step()

    # ── PULSE ────────────────────────────────────────────────
    def _pulse(self):
        if not self.anim_on:
            return
        v = int(180 + 75 * math.sin(time.time() * 2))
        v = max(0, min(255, v))
        color = f"#{v:02x}f5ff" if v < 128 else f"#00{v:02x}ff"
        try:
            self.hdr.itemconfig(self.hdr_title, fill=color)
        except Exception:
            pass
        self.root.after(80, self._pulse)

    # ============================================================
    #                   LOGIN
    # ============================================================
    def _login(self):
        username = self._lf_user.get().strip()
        password = self._lf_pw.get()

        if not username or not password:
            self._shake()
            messagebox.showerror("Missing",
                "Username and password are required!", parent=self.root)
            return

        if username in lockout_time:
            rem = int(lockout_time[username] - time.time())
            if rem > 0:
                messagebox.showerror("Locked",
                    f"Account locked.\nTry again in {rem} seconds.",
                    parent=self.root)
                return
            else:
                del lockout_time[username]
                failed_attempts[username] = 0

        cursor.execute(
            "SELECT password, login_count FROM users WHERE username=?",
            (username,)
        )
        row = cursor.fetchone()

        if not row:
            self._shake()
            log_activity("Login — user not found", username, "FAIL")
            messagebox.showerror("Not Found",
                "No account with that username.", parent=self.root)
            return

        stored_hash, login_count = row
        if bcrypt.checkpw(password.encode(), stored_hash):
            failed_attempts[username] = 0
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "UPDATE users SET last_login=?, login_count=? WHERE username=?",
                (now, (login_count or 0) + 1, username)
            )
            conn.commit()
            log_activity("Successful login", username, "LOGIN")
            self.status_var.set(f"Logged in as {username}")
            self._open_dashboard(username)
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            log_activity("Failed login", username, "FAIL")
            rem_att = MAX_ATTEMPTS - failed_attempts[username]
            if failed_attempts[username] >= MAX_ATTEMPTS:
                lockout_time[username] = time.time() + LOCK_TIME
                messagebox.showerror("Locked",
                    "Too many failed attempts!\nAccount locked for 60 seconds.",
                    parent=self.root)
            else:
                self._shake()
                messagebox.showerror("Wrong Password",
                    f"Invalid password!\n{rem_att} attempt(s) remaining.",
                    parent=self.root)

    # ============================================================
    #                   REGISTER
    # ============================================================
    def _register(self):
        username = self._rf_user.get().strip()
        email    = self._rf_email.get().strip()
        password = self._rf_pw.get()
        confirm  = self._rf_conf.get()
        sec_q    = self._rf_sq_var.get()
        sec_a    = self._rf_ans.get().strip().lower()

        if not all([username, password, confirm, sec_a]):
            self._shake()
            messagebox.showerror("Missing Fields",
                "Username, password, confirm password & security answer are required!",
                parent=self.root)
            return

        if password != confirm:
            messagebox.showerror("Mismatch",
                "Passwords do not match!", parent=self.root)
            return

        score, level, *_ = check_strength(password)
        if score < 4:
            messagebox.showerror("Weak Password",
                f"Strength: {level}\nPlease choose a stronger password.",
                parent=self.root)
            return

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            cursor.execute(
                "INSERT INTO users "
                "(username, email, password, security_question, security_answer)"
                " VALUES (?, ?, ?, ?, ?)",
                (username, email or None, hashed, sec_q, sec_a)
            )
            conn.commit()
            log_activity("User registered", username, "REGISTER")
            self.status_var.set(f"Account created for {username}")
            messagebox.showinfo("Success",
                f"Account created successfully!\nWelcome, {username}!",
                parent=self.root)
            self._clear_register()
            self._switch("login")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error",
                "Username already exists! Try a different one.",
                parent=self.root)

    # ============================================================
    #                   RESET PASSWORD
    # ============================================================
    def _reset(self):
        username = self._rs_user.get().strip()
        sec_a    = self._rs_ans.get().strip().lower()
        new_pw   = self._rs_pw.get()
        confirm  = self._rs_conf.get()

        if not all([username, sec_a, new_pw, confirm]):
            self._shake()
            messagebox.showerror("Missing",
                "All fields are required for password reset!", parent=self.root)
            return

        if new_pw != confirm:
            messagebox.showerror("Mismatch",
                "Passwords do not match!", parent=self.root)
            return

        score, level, *_ = check_strength(new_pw)
        if score < 4:
            messagebox.showerror("Weak Password",
                f"Strength: {level}\nChoose a stronger password.",
                parent=self.root)
            return

        cursor.execute(
            "SELECT security_answer FROM users WHERE username=?", (username,)
        )
        row = cursor.fetchone()

        if not row:
            messagebox.showerror("Not Found",
                "No account with that username.", parent=self.root)
            return

        if sec_a != row[0]:
            self._shake()
            log_activity("Failed reset — wrong answer", username, "FAIL")
            messagebox.showerror("Wrong Answer",
                "Security answer is incorrect!", parent=self.root)
            return

        hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt())
        cursor.execute(
            "UPDATE users SET password=? WHERE username=?", (hashed, username)
        )
        conn.commit()
        log_activity("Password reset successful", username, "RESET")
        self.status_var.set(f"Password reset for {username}")
        messagebox.showinfo("Success",
            "Password reset successful!", parent=self.root)
        self._clear_reset()
        self._switch("login")

    # ============================================================
    #                   DASHBOARD
    # ============================================================
    def _open_dashboard(self, username):
        cursor.execute(
            "SELECT email, last_login, login_count, created_at "
            "FROM users WHERE username=?",
            (username,)
        )
        row = cursor.fetchone() or ("—", "—", 0, "—")
        email, last_login, login_count, created_at = row

        dash = tk.Toplevel(self.root)
        dash.title(f"Dashboard — {username}")
        dash.geometry("460x540")
        dash.resizable(False, False)
        dash.configure(bg=C["bg"])

        # Center dashboard
        dash.update_idletasks()
        sw = dash.winfo_screenwidth()
        sh = dash.winfo_screenheight()
        dash.geometry(f"460x540+{(sw-460)//2}+{(sh-540)//2}")

        # Header
        hdr = tk.Canvas(dash, width=460, height=90,
                        bg=C["bg"], highlightthickness=0)
        hdr.pack(fill="x")
        for i in range(90):
            r = max(0, min(255, 10 + i // 6))
            b = max(0, min(255, 20 + i // 3))
            hdr.create_rectangle(0, i, 460, i + 1,
                                  fill=f"#{r:02x}0a{b:02x}", outline="")
        for x in range(0, 460, 40):
            hdr.create_line(x, 0, x, 90, fill="#2a2a3a", width=1)
        hdr.create_text(230, 35, text="SECURE DASHBOARD",
                        font=("Courier New", 18, "bold"), fill=C["cyan"])
        hdr.create_text(230, 58,
                        text=f"SESSION ACTIVE  |  USER: {username.upper()}",
                        font=F["sm"], fill=C["dim"])
        hdr.create_line(30, 74, 430, 74, fill=C["cyan"], width=1)
        hdr.create_oval(24, 70, 36, 78, fill=C["cyan"], outline="")
        hdr.create_oval(424, 70, 436, 78, fill=C["purple"], outline="")

        # Card
        card = tk.Frame(dash, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        card.pack(fill="both", expand=True, padx=14, pady=10)

        # Avatar
        av = tk.Canvas(card, width=72, height=72,
                       bg=C["card"], highlightthickness=0)
        av.pack(pady=(16, 0))
        av.create_oval(4, 4, 68, 68,
                       fill=C["purple"], outline=C["cyan"], width=2)
        av.create_text(36, 36, text=username[0].upper(),
                       font=("Courier New", 24, "bold"), fill="white")

        tk.Label(card, text=username,
                 font=("Courier New", 14, "bold"),
                 bg=C["card"], fg=C["fg"]).pack(pady=(4, 0))
        tk.Label(card,
                 text=email if email else "No email provided",
                 font=F["sm"], bg=C["card"], fg=C["dim"]).pack()

        tk.Frame(card, bg=C["border"], height=1).pack(fill="x", padx=16, pady=10)

        stats = [
            ("LAST LOGIN",     last_login or "First login!"),
            ("TOTAL LOGINS",   str(login_count or 1)),
            ("MEMBER SINCE",   (created_at or "")[:10]),
            ("ACCOUNT STATUS", "ACTIVE & SECURE"),
        ]
        for lbl, val in stats:
            row_f = tk.Frame(card, bg=C["inp"],
                             highlightbackground=C["border"], highlightthickness=1)
            row_f.pack(fill="x", padx=14, pady=2)
            tk.Label(row_f, text=f"  {lbl}", font=F["lbl"],
                     bg=C["inp"], fg=C["dim"],
                     anchor="w", pady=7).pack(side="left")
            tk.Label(row_f, text=f"{val}  ", font=F["mono"],
                     bg=C["inp"], fg=C["cyan"],
                     anchor="e").pack(side="right")

        tk.Frame(card, bg=C["border"], height=1).pack(fill="x", padx=16, pady=10)

        lo = tk.Label(card, text="   LOGOUT", font=F["btn"],
                      bg=C["red"], fg="white", cursor="hand2", pady=9)
        lo.pack(fill="x", padx=14, pady=4)
        lo.bind("<Button-1>", lambda e: dash.destroy())
        lo.bind("<Enter>",    lambda e: lo.config(bg="#cc0000"))
        lo.bind("<Leave>",    lambda e: lo.config(bg=C["red"]))


# ============================================================
#                       ENTRY POINT
# ============================================================
if __name__ == "__main__":
    App()