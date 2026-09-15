"""
ARPGuardInstaller.py
---------------------
GUI installer AND launcher for ARP Guard, in one .exe.

Behavior:
  - FIRST RUN: shows the full setup wizard - pick an install folder,
    checks/installs Python and Npcap if missing, downloads ARP Guard
    from GitHub, installs dependencies, then launches it.
  - EVERY RUN AFTER: detects the previous install (via a small config
    file) and skips straight to a "Launch Dashboard" screen - one
    click starts the agent and opens the browser. No re-running setup.

Must run as Administrator - installing Python/Npcap system-wide and
the agent's own firewall commands both require it. Elevates itself
automatically if not already running as admin.

Build into a standalone .exe with PyInstaller - see the build
instructions at the bottom of this file.
"""

import ctypes
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import webbrowser
import zipfile
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---- Configuration - update if the repo/branch/folder names change ----
GITHUB_OWNER = "arthghori"
GITHUB_REPO = "ARP-Guard"
GITHUB_BRANCH_CANDIDATES = ["main", "master"]  # tried in order until one works
# Matches: https://github.com/arthghori/ARP-Guard/tree/main/arpguard-windows
GITHUB_BASE_SUBFOLDER_TEMPLATE = "{repo}-{branch}/arpguard-windows/"
PYTHON_INSTALLER_URL = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
NPCAP_INSTALLER_URL = "https://npcap.com/dist/npcap-1.79.exe"  # check npcap.com for the latest version
DASHBOARD_URL = "http://127.0.0.1:8000"

# Where we remember "ARP Guard is already installed at <path>" between runs
CONFIG_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.environ.get("TEMP", ".")), "ARPGuardInstaller")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")


# ---------------------------------------------------------------------
# Admin elevation
# ---------------------------------------------------------------------

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def relaunch_as_admin():
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def npcap_installed() -> bool:
    try:
        result = subprocess.run(["sc", "query", "npcap"], capture_output=True, text=True)
        return "SERVICE_NAME" in result.stdout
    except Exception:
        return False


def wait_for_dashboard(timeout: int = 25) -> bool:
    """
    Polls the dashboard URL until it actually responds, instead of
    blindly sleeping a fixed number of seconds and hoping the server
    is up by then - that's what caused "site can't be reached" before,
    since a fixed short sleep isn't always enough (or the agent might
    have failed to start at all, e.g. Npcap missing or not elevated).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(DASHBOARD_URL, timeout=1.5)
            return True
        except Exception:
            time.sleep(1)
    return False


# ---------------------------------------------------------------------
# Config persistence (remembers install location between runs)
# ---------------------------------------------------------------------

def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_config(install_dir: str):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump({"install_dir": install_dir}, f)


def find_existing_install():
    """Returns the remembered install_dir if it still looks valid, else None."""
    config = load_config()
    if not config:
        return None
    install_dir = config.get("install_dir")
    if install_dir and os.path.exists(os.path.join(install_dir, "main.py")):
        return install_dir
    return None


# ---------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------

BG = "#0a0e14"
PANEL = "#11161f"
TEXT = "#e8eaed"
MUTED = "#6b7685"
SAFE = "#3ddc84"
LOGBG = "#0d1219"


class InstallerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Guard")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)
        self.log_queue = queue.Queue()

        existing = find_existing_install()
        if existing:
            self.install_dir = existing
            self._build_launch_view()
        else:
            self.install_dir = None
            self._build_wizard_view()

        self.root.after(100, self._poll_log)

    # ---- shared log helper ----

    def log(self, msg):
        self.log_queue.put(msg)

    def _poll_log(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                if hasattr(self, "log_box"):
                    self.log_box.configure(state="normal")
                    self.log_box.insert("end", msg + "\n")
                    self.log_box.see("end")
                    self.log_box.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_log)

    # ===================================================================
    # VIEW 1: Already installed -> one-click launch screen
    # ===================================================================

    def _build_launch_view(self):
        self.root.geometry("480x400")
        self.root.minsize(420, 360)
        self.root.resizable(True, True)

        tk.Label(self.root, text="ARP Guard", font=("Segoe UI", 20, "bold"),
                 bg=BG, fg=TEXT).pack(pady=(28, 4))
        tk.Label(self.root, text="Already installed on this machine.",
                 bg=BG, fg=MUTED).pack()
        tk.Label(self.root, text=self.install_dir, bg=BG, fg=MUTED,
                 font=("Consolas", 9)).pack(pady=(2, 20))

        # Bottom button row is packed FIRST with side="bottom" so it
        # always claims its space and is never pushed off-screen by
        # the expanding log box above it, regardless of window size
        # or DPI scaling differences between machines.
        bottom = tk.Frame(self.root, bg=BG)
        bottom.pack(side="bottom", pady=(8, 16))
        tk.Button(bottom, text="Run setup again", command=self._switch_to_wizard,
                  relief="flat", fg=MUTED, bg=BG).pack(side="left", padx=6)
        tk.Button(bottom, text="Exit", command=self.root.quit, relief="flat").pack(side="left", padx=6)

        self.launch_btn = tk.Button(
            self.root, text="Launch Dashboard", command=self.do_launch,
            width=24, height=2, bg=SAFE, fg="#04241a", relief="flat",
            font=("Segoe UI", 11, "bold"),
        )
        self.launch_btn.pack(pady=(0, 10))

        self.log_box = tk.Text(self.root, height=6, bg=LOGBG, fg=TEXT,
                                font=("Consolas", 9), relief="flat")
        self.log_box.pack(fill="both", expand=True, padx=24, pady=(4, 12))
        self.log_box.configure(state="disabled")

        # Auto-launch shortly after the window appears - no click needed
        # on repeat runs. The button stays available too, in case
        # auto-launch fails and the person wants to retry manually.
        self.root.after(400, self.do_launch)

    def _switch_to_wizard(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.install_dir = None
        self._build_wizard_view()

    def do_launch(self):
        self.launch_btn.configure(state="disabled", text="Starting...")
        threading.Thread(target=self._launch_thread, daemon=True).start()

    def _launch_thread(self):
        try:
            self.step_launch()
        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("ARP Guard", f"Could not launch:\n{e}")
        finally:
            self.launch_btn.configure(state="normal", text="Launch Dashboard")

    # ===================================================================
    # VIEW 2: First-time setup wizard
    # ===================================================================

    def _build_wizard_view(self):
        self.root.geometry("600x700")
        self.root.minsize(560, 560)
        self.root.resizable(True, True)

        tk.Label(self.root, text="ARP Guard Installer", font=("Segoe UI", 16, "bold"),
                 bg=BG, fg=TEXT).pack(pady=(16, 4))
        tk.Label(self.root, text="Sets up ARP Guard on this Windows machine.",
                 bg=BG, fg=MUTED).pack()

        # Bottom button row is packed FIRST with side="bottom" so it
        # always claims its space at the bottom of the window and can
        # never be pushed off-screen by the expanding log box above it -
        # this is what was cut off before on some screens/DPI settings.
        btn_frame = tk.Frame(self.root, bg=BG)
        btn_frame.pack(side="bottom", pady=(10, 18))
        self.start_btn = tk.Button(btn_frame, text="Start installation", command=self.start_install,
                                    width=20, bg=SAFE, fg="#04241a", relief="flat",
                                    font=("Segoe UI", 10, "bold"))
        self.start_btn.pack(side="left", padx=6)
        tk.Button(btn_frame, text="Exit", command=self.root.quit, width=12, relief="flat").pack(side="left", padx=6)

        # --- install location picker ---
        path_frame = tk.LabelFrame(self.root, text="Install location", padx=12, pady=10,
                                    bg=PANEL, fg=TEXT)
        path_frame.pack(fill="x", padx=24, pady=(14, 0))

        default_base = os.environ.get("USERPROFILE", "C:\\")
        self.base_dir_var = tk.StringVar(value=default_base)

        entry_row = tk.Frame(path_frame, bg=PANEL)
        entry_row.pack(fill="x")
        tk.Entry(entry_row, textvariable=self.base_dir_var, width=48).pack(side="left", padx=(0, 8))
        tk.Button(entry_row, text="Browse...", command=self._browse_folder, relief="flat").pack(side="left")

        tk.Label(path_frame, text="An \"ARPGuard\" folder will be created inside the path above.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 0))

        # --- options ---
        options_frame = tk.LabelFrame(self.root, text="Install options", padx=14, pady=10,
                                       bg=PANEL, fg=TEXT)
        options_frame.pack(fill="x", padx=24, pady=14)

        self.var_python = tk.BooleanVar(value=True)
        self.var_npcap = tk.BooleanVar(value=True)
        self.var_download = tk.BooleanVar(value=True)
        self.var_deps = tk.BooleanVar(value=True)
        self.var_launch = tk.BooleanVar(value=True)

        opts = [
            (self.var_python, "Install Python (if missing)"),
            (self.var_npcap, "Install Npcap (if missing)"),
            (self.var_download, "Download ARP Guard from GitHub"),
            (self.var_deps, "Install Python dependencies"),
            (self.var_launch, "Launch agent + open dashboard when done"),
        ]
        for var, label in opts:
            tk.Checkbutton(options_frame, text=label, variable=var, bg=PANEL, fg=TEXT,
                            selectcolor=LOGBG, activebackground=PANEL, activeforeground=TEXT,
                            anchor="w").pack(fill="x", anchor="w")

        self.progress = ttk.Progressbar(self.root, mode="determinate", maximum=100)
        self.progress.pack(fill="x", padx=24, pady=(4, 10))

        self.log_box = tk.Text(self.root, height=8, bg=LOGBG, fg=TEXT,
                                font=("Consolas", 9), relief="flat")
        self.log_box.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        self.log_box.configure(state="disabled")

    def _browse_folder(self):
        chosen = filedialog.askdirectory(initialdir=self.base_dir_var.get())
        if chosen:
            self.base_dir_var.set(chosen)

    def start_install(self):
        self.install_dir = os.path.join(self.base_dir_var.get(), "ARPGuard")
        self.start_btn.configure(state="disabled")
        threading.Thread(target=self.run_install, daemon=True).start()

    def run_install(self):
        try:
            steps = []
            if self.var_python.get():
                steps.append(self.step_python)
            if self.var_npcap.get():
                steps.append(self.step_npcap)
            if self.var_download.get():
                steps.append(self.step_download)
            if self.var_deps.get():
                steps.append(self.step_deps)

            total = len(steps) or 1
            for i, step in enumerate(steps):
                step()
                self.progress["value"] = int((i + 1) / total * 100)

            save_config(self.install_dir)
            self.log("")
            self.log(f"Installed to: {self.install_dir}")
            self.log("Setup remembered - next time you open this app, it will launch directly.")

            if self.var_launch.get():
                self.step_launch()

            self.log("Installation complete.")
            messagebox.showinfo("ARP Guard", "Installation complete.\n\n"
                                 "If the dashboard didn't open automatically, "
                                 "visit http://127.0.0.1:8000 manually.")
        except subprocess.CalledProcessError as e:
            self.log(f"ERROR: command failed: {e}")
            messagebox.showerror("ARP Guard Installer", f"A command failed:\n{e}")
        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("ARP Guard Installer", f"Something went wrong:\n{e}")
        finally:
            self.start_btn.configure(state="normal")

    # ===================================================================
    # Shared install/launch steps
    # ===================================================================

    def step_python(self):
        self.log("Checking for Python...")
        if command_exists("python"):
            self.log("  Python already installed - skipping.")
            return

        self.log("  Python not found.")
        if command_exists("winget"):
            self.log("  Installing via winget (this may take a minute)...")
            subprocess.run(
                ["winget", "install", "-e", "--id", "Python.Python.3.12",
                 "--silent", "--accept-package-agreements", "--accept-source-agreements"],
                check=True,
            )
            self.log("  Python installed via winget.")
            return

        self.log("  winget not available - downloading installer directly...")
        installer_path = os.path.join(os.environ["TEMP"], "python_installer.exe")
        urllib.request.urlretrieve(PYTHON_INSTALLER_URL, installer_path)
        self.log("  Installing Python silently...")
        subprocess.run([installer_path, "/quiet", "InstallAllUsers=1", "PrependPath=1"], check=True)
        self.log("  Python installed.")
        self.log("  NOTE: if later steps can't find 'python', close and re-run "
                  "this installer so the updated PATH takes effect.")

    def step_npcap(self):
        self.log("Checking for Npcap...")
        if npcap_installed():
            self.log("  Npcap already installed - skipping.")
            return

        self.log("  Npcap not found. Downloading installer...")
        installer_path = os.path.join(os.environ["TEMP"], "npcap_installer.exe")
        urllib.request.urlretrieve(NPCAP_INSTALLER_URL, installer_path)
        self.log("  Installing Npcap silently (WinPcap-compatible mode)...")
        subprocess.run([installer_path, "/S", "/winpcap_mode=yes"], check=True)
        self.log("  Npcap installed.")

    def step_download(self):
        self.log(f"Downloading ARP Guard to {self.install_dir} ...")
        os.makedirs(self.install_dir, exist_ok=True)
        zip_path = os.path.join(os.environ["TEMP"], "arpguard.zip")

        # Try each candidate branch name until one actually downloads -
        # this way the script doesn't need to hardcode whether the repo's
        # default branch is called "main" or "master".
        last_error = None
        working_branch = None
        for branch in GITHUB_BRANCH_CANDIDATES:
            url = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/archive/refs/heads/{branch}.zip"
            self.log(f"  Trying branch '{branch}'...")
            try:
                urllib.request.urlretrieve(url, zip_path)
                working_branch = branch
                self.log(f"  Found it on branch '{branch}'.")
                break
            except urllib.error.HTTPError as e:
                last_error = e
                self.log(f"  Branch '{branch}' failed ({e.code} {e.reason}), trying next...")
                continue

        if working_branch is None:
            raise RuntimeError(
                f"Could not download from any of these branches: {GITHUB_BRANCH_CANDIDATES}\n"
                f"Owner/repo: {GITHUB_OWNER}/{GITHUB_REPO}\n"
                f"Last error: {last_error}\n\n"
                f"Open https://github.com/{GITHUB_OWNER}/{GITHUB_REPO} in a browser and confirm:\n"
                f"  - the repo name/owner are typed exactly right\n"
                f"  - the branch dropdown shows a name not listed above - if so, add it to "
                f"GITHUB_BRANCH_CANDIDATES in the script"
            )

        subfolder = GITHUB_BASE_SUBFOLDER_TEMPLATE.format(repo=GITHUB_REPO, branch=working_branch)

        self.log("  Extracting files...")
        with zipfile.ZipFile(zip_path, "r") as zf:
            extracted = 0
            for member in zf.namelist():
                if not (member.startswith(subfolder) and not member.endswith("/")):
                    continue

                relative_path = member[len(subfolder):]
                if not relative_path:
                    continue

                # Safety net: if the repo still has main.py/requirements.txt
                # inside an extra "agent/" folder while other code folders
                # (api/, dashboard/, etc.) sit as its siblings instead of
                # inside it, flatten "agent/" out so everything lands
                # together the way main.py's imports actually expect. If
                # the repo structure is already correct (everything inside
                # agent/), this is a harmless no-op.
                if relative_path.startswith("agent/"):
                    relative_path = relative_path[len("agent/"):]
                if not relative_path:
                    continue

                target_path = os.path.join(self.install_dir, relative_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with zf.open(member) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                extracted += 1

        if extracted == 0:
            raise RuntimeError(
                f"Downloaded the zip successfully, but found no files under '{subfolder}'.\n"
                f"Check the repo's file listing on GitHub to confirm the 'arpguard-windows' "
                f"folder exists at the repo root."
            )
        self.log(f"  Extracted {extracted} file(s).")

    def step_deps(self):
        self.log("Installing Python dependencies...")
        requirements_path = os.path.join(self.install_dir, "requirements.txt")
        if not os.path.exists(requirements_path):
            self.log("  requirements.txt not found - skipping (check the download step).")
            return
        subprocess.run(
            ["python", "-m", "pip", "install", "-r", requirements_path],
            check=True, cwd=self.install_dir,
        )
        self.log("  Dependencies installed.")

    def step_launch(self):
        self.log("Launching ARP Guard agent...")
        main_py = os.path.join(self.install_dir, "main.py")
        if not os.path.exists(main_py):
            self.log("  main.py not found - cannot launch.")
            return

        # Its own console window, since the agent needs to keep running
        # and show live logs even though this installer/launcher window
        # has no console of its own.
        subprocess.Popen(
            ["python", "main.py"],
            cwd=self.install_dir,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
        self.log("  Waiting for the dashboard to come online...")

        if wait_for_dashboard(timeout=25):
            webbrowser.open(DASHBOARD_URL)
            self.log(f"  Dashboard opened: {DASHBOARD_URL}")
        else:
            self.log("  Dashboard did not respond within 25 seconds.")
            raise RuntimeError(
                "The agent's console window opened, but the dashboard never came online.\n\n"
                "Check the ARP Guard console window that opened separately - it will show "
                "the actual error. Common causes:\n"
                "  - Npcap isn't installed, or wasn't set to WinPcap-compatible mode\n"
                "  - Not actually running as Administrator\n"
                "  - No network connection (agent can't find a default gateway)\n"
                "  - 'python' isn't on PATH yet if Python was just installed - "
                "try closing everything and running this app again"
            )


def main():
    if not is_admin():
        relaunch_as_admin()
        return

    root = tk.Tk()
    InstallerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()


# =======================================================================
# BUILDING THIS INTO A STANDALONE .EXE
# =======================================================================
#
# On a Windows machine with Python installed, with icon.ico sitting in
# the same folder as this script:
#
#   pip install pyinstaller
#   pyinstaller --onefile --windowed --uac-admin --icon=icon.ico --name ARPGuard ARPGuardInstaller.py
#
# What each flag does:
#   --onefile     bundles everything into a single .exe
#   --windowed    no console window behind the GUI (it's a Tkinter app)
#   --uac-admin   embeds a manifest so Windows prompts for Administrator
#                 automatically when the .exe is double-clicked
#   --icon        sets the .exe's icon (shown in Explorer, taskbar, and
#                 the title bar) - needs a .ico file, not .png
#   --name        output filename (ARPGuard.exe)
#
# The finished .exe lands in the dist/ folder. Hand that single file
# to anyone: first double-click runs the setup wizard (with a folder
# picker), every double-click after that goes straight to a
# "Launch Dashboard" button - same .exe, two behaviors.
# =======================================================================
