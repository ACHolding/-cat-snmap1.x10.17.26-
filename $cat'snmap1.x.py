#!/usr/bin/env python3
"""Cat's nmap 1.x — tkinter GUI with pre-baked nmap."""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk


# Theme
BG = "#0a1a3a"
BG_PANEL = "#0f2248"
FG = "#5eb0ff"
FG_DIM = "#3a7ab8"
BTN_BG = "#000000"
BTN_FG = "#5eb0ff"
BTN_ACTIVE = "#1a1a1a"
ENTRY_BG = "#061028"
ENTRY_FG = "#5eb0ff"
ACCENT = "#1e90ff"

WINDOW_W = 1920
WINDOW_H = 1080
TITLE = "Cat's nmap 1.x"

APP_DIR = Path(__file__).resolve().parent
VENDOR_NMAP = APP_DIR / "vendor" / "nmap"
BUNDLED_NMAP = VENDOR_NMAP / "bin" / "nmap"
BUNDLED_NMAPDIR = VENDOR_NMAP / "share" / "nmap"


def resolve_nmap() -> tuple[str | None, dict[str, str]]:
    """Prefer the pre-baked vendor/nmap binary; fall back to system PATH."""
    env: dict[str, str] = {}
    if BUNDLED_NMAP.is_file() and os.access(BUNDLED_NMAP, os.X_OK):
        if BUNDLED_NMAPDIR.is_dir():
            env["NMAPDIR"] = str(BUNDLED_NMAPDIR)
        return str(BUNDLED_NMAP), env
    system = shutil.which("nmap")
    return (system, env) if system else (None, env)


class CatsNmapApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(TITLE)
        self.configure(bg=BG)
        self._center_window(WINDOW_W, WINDOW_H)
        self.resizable(True, True)
        self.minsize(960, 540)

        self._scan_proc = None
        self._scanning = False
        self.nmap_path, self.nmap_env = resolve_nmap()

        self._build_ui()
        self._check_nmap()

    def _center_window(self, width: int, height: int) -> None:
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - width) // 2)
        y = max(0, (sh - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _check_nmap(self) -> None:
        if not self.nmap_path:
            self.after(
                200,
                lambda: messagebox.showwarning(
                    TITLE,
                    "Bundled nmap is missing (vendor/nmap).\n"
                    "Reinstall the app bundle or install nmap on PATH.",
                ),
            )
            return
        source = "bundled" if self.nmap_path.startswith(str(VENDOR_NMAP)) else "system"
        self.status_var.set(f"Ready · {source} nmap")

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Blue.TFrame", background=BG)
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure(
            "Blue.TLabel",
            background=BG,
            foreground=FG,
            font=("Helvetica", 12),
        )
        style.configure(
            "Title.TLabel",
            background=BG,
            foreground=ACCENT,
            font=("Helvetica", 28, "bold"),
        )
        style.configure(
            "Dim.TLabel",
            background=BG,
            foreground=FG_DIM,
            font=("Helvetica", 10),
        )
        style.configure(
            "Panel.TLabelframe",
            background=BG_PANEL,
            foreground=FG,
            bordercolor=ACCENT,
            font=("Helvetica", 11, "bold"),
        )
        style.configure(
            "Panel.TLabelframe.Label",
            background=BG_PANEL,
            foreground=ACCENT,
            font=("Helvetica", 11, "bold"),
        )
        style.configure(
            "Blue.TCheckbutton",
            background=BG_PANEL,
            foreground=FG,
            font=("Helvetica", 11),
        )
        style.map(
            "Blue.TCheckbutton",
            background=[("active", BG_PANEL)],
            foreground=[("active", FG)],
        )

        root = ttk.Frame(self, style="Blue.TFrame", padding=24)
        root.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Frame(root, style="Blue.TFrame")
        header.pack(fill=tk.X, pady=(0, 16))
        ttk.Label(header, text=TITLE, style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(
            header,
            text="authorized network discovery only",
            style="Dim.TLabel",
        ).pack(side=tk.RIGHT, pady=12)

        # Target row
        target_row = ttk.Frame(root, style="Blue.TFrame")
        target_row.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(target_row, text="Target", style="Blue.TLabel").pack(
            side=tk.LEFT, padx=(0, 12)
        )
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = tk.Entry(
            target_row,
            textvariable=self.target_var,
            bg=ENTRY_BG,
            fg=ENTRY_FG,
            insertbackground=FG,
            relief=tk.FLAT,
            font=("Menlo", 14),
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
        )
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)

        # Options
        opts = ttk.LabelFrame(
            root, text=" Scan options ", style="Panel.TLabelframe", padding=16
        )
        opts.pack(fill=tk.X, pady=(0, 12))

        self.opt_syn = tk.BooleanVar(value=True)
        self.opt_service = tk.BooleanVar(value=False)
        self.opt_os = tk.BooleanVar(value=False)
        self.opt_ping = tk.BooleanVar(value=False)
        self.opt_udp = tk.BooleanVar(value=False)
        self.opt_verbose = tk.BooleanVar(value=True)

        checks = [
            (self.opt_syn, "SYN scan (-sS)"),
            (self.opt_service, "Service/version (-sV)"),
            (self.opt_os, "OS detection (-O)"),
            (self.opt_ping, "Ping only (-sn)"),
            (self.opt_udp, "UDP scan (-sU)"),
            (self.opt_verbose, "Verbose (-v)"),
        ]
        for i, (var, label) in enumerate(checks):
            cb = ttk.Checkbutton(
                opts, text=label, variable=var, style="Blue.TCheckbutton"
            )
            cb.grid(row=i // 3, column=i % 3, sticky=tk.W, padx=12, pady=6)

        ports_row = ttk.Frame(opts, style="Panel.TFrame")
        ports_row.grid(row=2, column=0, columnspan=3, sticky=tk.EW, pady=(8, 0))
        tk.Label(
            ports_row, text="Ports", bg=BG_PANEL, fg=FG, font=("Helvetica", 12)
        ).pack(side=tk.LEFT, padx=(0, 12))
        self.ports_var = tk.StringVar(value="")
        self.ports_entry = tk.Entry(
            ports_row,
            textvariable=self.ports_var,
            bg=ENTRY_BG,
            fg=ENTRY_FG,
            insertbackground=FG,
            relief=tk.FLAT,
            font=("Menlo", 12),
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
            width=40,
        )
        self.ports_entry.pack(side=tk.LEFT, ipady=4)
        tk.Label(
            ports_row,
            text="e.g. 22,80,443 or 1-1024  (empty = nmap default)",
            bg=BG_PANEL,
            fg=FG_DIM,
            font=("Helvetica", 10),
        ).pack(side=tk.LEFT, padx=12)

        extra_row = ttk.Frame(opts, style="Panel.TFrame")
        extra_row.grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=(8, 0))
        tk.Label(
            extra_row, text="Extra args", bg=BG_PANEL, fg=FG, font=("Helvetica", 12)
        ).pack(side=tk.LEFT, padx=(0, 12))
        self.extra_var = tk.StringVar(value="")
        self.extra_entry = tk.Entry(
            extra_row,
            textvariable=self.extra_var,
            bg=ENTRY_BG,
            fg=ENTRY_FG,
            insertbackground=FG,
            relief=tk.FLAT,
            font=("Menlo", 12),
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
        )
        self.extra_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)

        # Buttons
        btn_row = ttk.Frame(root, style="Blue.TFrame")
        btn_row.pack(fill=tk.X, pady=(0, 12))

        self.scan_btn = self._make_button(btn_row, "Scan", self._on_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.stop_btn = self._make_button(btn_row, "Stop", self._on_stop)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.stop_btn.configure(state=tk.DISABLED)

        self.clear_btn = self._make_button(btn_row, "Clear", self._on_clear)
        self.clear_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(
            btn_row,
            textvariable=self.status_var,
            bg=BG,
            fg=FG_DIM,
            font=("Helvetica", 11),
        ).pack(side=tk.RIGHT)

        # Output
        out_frame = ttk.LabelFrame(
            root, text=" Output ", style="Panel.TLabelframe", padding=8
        )
        out_frame.pack(fill=tk.BOTH, expand=True)

        self.output = scrolledtext.ScrolledText(
            out_frame,
            bg=ENTRY_BG,
            fg=FG,
            insertbackground=FG,
            relief=tk.FLAT,
            font=("Menlo", 12),
            wrap=tk.WORD,
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
        )
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.configure(state=tk.DISABLED)

    def _make_button(self, parent, text: str, command) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=BTN_BG,
            fg=BTN_FG,
            activebackground=BTN_ACTIVE,
            activeforeground=FG,
            disabledforeground=FG_DIM,
            relief=tk.FLAT,
            font=("Helvetica", 12, "bold"),
            padx=24,
            pady=10,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
        )

    def _append_output(self, text: str) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.configure(state=tk.DISABLED)

    def _set_scanning(self, active: bool) -> None:
        self._scanning = active
        self.scan_btn.configure(state=tk.DISABLED if active else tk.NORMAL)
        self.stop_btn.configure(state=tk.NORMAL if active else tk.DISABLED)
        self.status_var.set("Scanning…" if active else "Ready")

    def _build_cmd(self) -> list[str] | None:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror(TITLE, "Enter a target host or network.")
            return None
        if not self.nmap_path:
            messagebox.showerror(TITLE, "Bundled nmap is missing.")
            return None

        cmd = [self.nmap_path]
        if self.opt_ping.get():
            cmd.append("-sn")
        else:
            if self.opt_syn.get():
                cmd.append("-sS")
            if self.opt_udp.get():
                cmd.append("-sU")
            if self.opt_service.get():
                cmd.append("-sV")
            if self.opt_os.get():
                cmd.append("-O")
            ports = self.ports_var.get().strip()
            if ports:
                cmd.extend(["-p", ports])
        if self.opt_verbose.get():
            cmd.append("-v")

        extra = self.extra_var.get().strip()
        if extra:
            cmd.extend(extra.split())

        cmd.append(target)
        return cmd

    def _on_scan(self) -> None:
        if self._scanning:
            return
        cmd = self._build_cmd()
        if not cmd:
            return

        self._on_clear()
        display = ["nmap", *cmd[1:]]
        self._append_output(f"$ {' '.join(display)}\n\n")
        self._set_scanning(True)

        thread = threading.Thread(target=self._run_scan, args=(cmd,), daemon=True)
        thread.start()

    def _run_scan(self, cmd: list[str]) -> None:
        try:
            env = os.environ.copy()
            env.update(self.nmap_env)
            self._scan_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            assert self._scan_proc.stdout is not None
            for line in self._scan_proc.stdout:
                self.after(0, self._append_output, line)
            code = self._scan_proc.wait()
            self.after(
                0,
                self._append_output,
                f"\n[exit {code}]\n",
            )
        except FileNotFoundError:
            self.after(
                0,
                lambda: messagebox.showerror(TITLE, "Bundled nmap is missing."),
            )
        except Exception as exc:
            self.after(0, self._append_output, f"\nError: {exc}\n")
        finally:
            self._scan_proc = None
            self.after(0, self._set_scanning, False)

    def _on_stop(self) -> None:
        proc = self._scan_proc
        if proc and proc.poll() is None:
            proc.terminate()
            self._append_output("\n[stopped]\n")
            self.status_var.set("Stopped")

    def _on_clear(self) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.configure(state=tk.DISABLED)


def main() -> None:
    app = CatsNmapApp()
    app.mainloop()


if __name__ == "__main__":
    main()
