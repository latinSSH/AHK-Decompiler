#   __         __   __
#  |  |.---.-.|  |_|__|.-----.
#  |  ||  _  ||   _|  ||     |
#  |__||___._||____|__||__|__|
#         noskid.today


import customtkinter as ctk
from customtkinter import CTk, CTkFrame, CTkLabel, CTkEntry, CTkButton, CTkComboBox
from customtkinter import CTkProgressBar, CTkTextbox, CTkTabview, StringVar
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import os
import threading
from pathlib import Path
import re

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class AHKDecompilerApp(CTk):
    def __init__(self):
        super().__init__()
        self.title("AHK Decompiler • Mango Edition V67")
        self.geometry("980x680")
        self.resizable(True, True)

        self.exe_path = StringVar(value="")
        self.output_dir = StringVar(value=str(Path.home() / "Desktop" / "AHK_Decompiled"))
        self.selected_mode = StringVar(value="Smart Attempt")
        self.status_var = StringVar(value="Ready")

        self._create_ui()
        self.log("Welcome to Modern AHK Decompiler\nReady when you are.\n", "highlight")

    def _create_ui(self):
        main_frame = CTkFrame(self, corner_radius=0)
        main_frame.pack(fill="both", expand=True)

        CTkLabel(main_frame, text="AutoHotkey EXE Decompiler", font=("Segoe UI", 24, "bold")).pack(pady=(20, 10))

        input_frame = CTkFrame(main_frame)
        input_frame.pack(fill="x", padx=30, pady=10)

        CTkLabel(input_frame, text="EXE File:", font=("Segoe UI", 14)).grid(row=0, column=0, padx=10, pady=8, sticky="w")
        CTkEntry(input_frame, textvariable=self.exe_path, width=500, height=36, font=("Consolas", 12)).grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        CTkButton(input_frame, text="Browse", width=100, command=self.browse_exe).grid(row=0, column=2, padx=8, pady=8)

        CTkLabel(input_frame, text="Output Folder:", font=("Segoe UI", 14)).grid(row=1, column=0, padx=10, pady=8, sticky="w")
        CTkEntry(input_frame, textvariable=self.output_dir, width=500, height=36, font=("Consolas", 12)).grid(row=1, column=1, padx=8, pady=8, sticky="ew")
        CTkButton(input_frame, text="Browse", width=100, command=self.browse_output).grid(row=1, column=2, padx=8, pady=8)

        input_frame.columnconfigure(1, weight=1)

        control_frame = CTkFrame(main_frame)
        control_frame.pack(fill="x", padx=30, pady=12)

        CTkLabel(control_frame, text="Decompile Mode:", font=("Segoe UI", 14)).pack(side="left", padx=(0,12))
        CTkComboBox(control_frame, values=[
            "Smart Attempt (recommended)",
            "Basic Resource Extract",
            "Brute-force Strings Scan"
        ], variable=self.selected_mode, width=240, state="readonly").pack(side="left", padx=8)

        CTkButton(control_frame, text="START DECOMPILE", width=220, height=45,
                  font=("Segoe UI", 14, "bold"), command=self.start_decompile_thread).pack(side="right", padx=20)

        self.progress = CTkProgressBar(main_frame, width=600, height=12, mode="determinate")
        self.progress.pack(pady=(10,4))
        self.progress.set(0)

        CTkLabel(main_frame, textvariable=self.status_var, font=("Segoe UI", 13)).pack(pady=(0,12))

        tabview = CTkTabview(main_frame, width=920, height=320)
        tabview.pack(padx=30, pady=10, fill="both", expand=True)

        tabview.add("Log")
        tabview.add("Preview Recovered Script")

        self.log_text = CTkTextbox(tabview.tab("Log"), font=("Consolas", 11), wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

        self.preview_text = CTkTextbox(tabview.tab("Preview Recovered Script"), font=("Consolas", 11))
        self.preview_text.pack(fill="both", expand=True, padx=6, pady=6)

        bottom_frame = CTkFrame(main_frame)
        bottom_frame.pack(fill="x", padx=30, pady=(0,20))

        CTkButton(bottom_frame, text="Open Output Folder", command=self.open_output).pack(side="left", padx=10)
        CTkButton(bottom_frame, text="Copy Preview to Clipboard", command=self.copy_preview).pack(side="left", padx=10)
        CTkButton(bottom_frame, text="Clear Log", command=self.clear_log, fg_color="transparent").pack(side="right", padx=10)

    def log(self, msg: str, tag="normal"):
        colors = {
            "normal": "#e0e0e0",
            "highlight": "#00ccff",
            "success": "#55ff99",
            "warning": "#ffcc66",
            "error": "#ff5555"
        }
        self.log_text.insert("end", msg + "\n", tag)
        self.log_text.tag_config(tag, foreground=colors.get(tag, "#e0e0e0"))
        self.log_text.see("end")
        self.update_idletasks()

    def clear_log(self):
        self.log_text.delete("1.0", "end")
        self.preview_text.delete("1.0", "end")
        self.progress.set(0)
        self.status_var.set("Ready")

    def set_progress(self, value: float):
        self.progress.set(value)
        self.update_idletasks()

    def browse_exe(self):
        path = filedialog.askopenfilename(filetypes=[("EXE files", "*.exe"), ("All", "*.*")])
        if path:
            self.exe_path.set(path)
            self.log(f"Selected: {path}\n", "highlight")

    def browse_output(self):
        path = filedialog.askdirectory()
        if path:
            self.output_dir.set(path)

    def open_output(self):
        path = self.output_dir.get().strip()
        if path and os.path.isdir(path):
            os.startfile(path)
        else:
            self.log("Output folder doesn't exist yet.\n", "warning")

    def copy_preview(self):
        text = self.preview_text.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.log("Preview copied.\n", "success")
        else:
            self.log("Nothing in preview to copy.\n", "warning")

    def start_decompile_thread(self):
        threading.Thread(target=self.decompile, daemon=True).start()

    def decompile(self):
        exe = self.exe_path.get().strip()
        out_dir = self.output_dir.get().strip()

        if not exe or not os.path.isfile(exe):
            self.log("No valid .exe selected.\n", "error")
            return

        if not out_dir:
            self.log("No output directory selected.\n", "error")
            return

        os.makedirs(out_dir, exist_ok=True)

        self.log(f"\nDecompiling...\nFile: {exe}\nOutput: {out_dir}\n", "highlight")
        self.status_var.set("Working...")
        self.progress.set(0.1)

        mode = self.selected_mode.get()
        recovered_path = None

        try:
            if "Smart" in mode:
                recovered_path = self.smart_attempt(exe, out_dir)
            elif "Resource" in mode:
                recovered_path = self.extract_resource(exe, out_dir)
            elif "Brute" in mode:
                recovered_path = self.brute_strings(exe, out_dir)

            if recovered_path and os.path.isfile(recovered_path):
                self.progress.set(0.95)
                self.log(f"\nSaved → {recovered_path}\n", "success")

                try:
                    with open(recovered_path, encoding="utf-8", errors="ignore") as f:
                        preview = f.read(2200)
                    self.preview_text.delete("1.0", "end")
                    self.preview_text.insert("end", preview + "\n\n[...]\n")
                except Exception as e:
                    self.log(f"Preview failed: {e}\n", "warning")
            else:
                self.log("\nFailed to recover a readable script.\n", "warning")
                self.log("Typical 2026 blockers:\n• Packed (UPX/MPRESS/custom)\n• Encrypted resource\n• AHK v2\n• Protection/stripping\n", "warning")

        except Exception as e:
            self.log(f"Error during decompile: {str(e)}\n", "error")

        self.progress.set(1.0)
        self.status_var.set("Finished")
        self.log("Operation complete.\n", "highlight")

        self.after(300, lambda: messagebox.showinfo(
            "Decompile Done",
            "To reformat the strings paste it into ChatGPT or smth idfk"
        ))

    def smart_attempt(self, exe: str, out_dir: str) -> str | None:
        self.log("Smart mode → trying multiple methods...\n", "normal")
        self.set_progress(0.2)

        path = self.extract_resource(exe, out_dir)
        if path:
            self.log("Got script from resource.\n", "success")
            return path

        self.set_progress(0.5)

        path = self.brute_strings(exe, out_dir)
        if path:
            self.log("Got partial script from strings scan.\n", "success")
            return path

        self.set_progress(0.8)
        return None

    def extract_resource(self, exe: str, out_dir: str) -> str | None:
        self.log("Trying resource extraction...\n", "normal")
        out_file = os.path.join(out_dir, Path(exe).stem + "_extracted.ahk")

        try:
            import pefile
            pe = pefile.PE(exe)
            for rsrc in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', []):
                for entry in rsrc.directory.entries:
                    for res in entry.directory.entries:
                        name = str(res.name).upper() if res.name else ""
                        if "AUTOHOTKEY" in name or "SCRIPT" in name:
                            data_rva = res.data.struct.OffsetToData
                            size = res.data.struct.Size
                            data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                            with open(out_file, "wb") as f:
                                f.write(data)
                            self.log(f"Extracted → {out_file}\n", "success")
                            return out_file
            self.log("No obvious AHK resource found.\n", "normal")
        except ImportError:
            self.log("pefile not installed → skipping PE scan (pip install pefile)\n", "warning")
        except Exception as e:
            self.log(f"Resource extraction error: {e}\n", "warning")
        return None

    def brute_strings(self, exe: str, out_dir: str) -> str | None:
        self.log("Scanning for AHK-like strings...\n", "normal")
        out_file = os.path.join(out_dir, Path(exe).stem + "_strings.ahk")

        try:
            with open(exe, "rb") as f:
                data = f.read()

            strings = []
            current = b""
            for b in data:
                if 32 <= b <= 126 or b in (9, 10, 13):
                    current += bytes([b])
                else:
                    if len(current) > 20:
                        try:
                            s = current.decode("utf-8", errors="ignore").strip()
                            if re.search(r"(?i)(send|click|run|if|else|loop|while|Gui|MsgBox|Hotkey|return)", s):
                                strings.append(s)
                        except:
                            pass
                    current = b""

            if strings:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(strings))
                self.log(f"Found {len(strings)} candidate lines → {out_file}\n", "success")
                return out_file
            else:
                self.log("No useful AHK-like strings found.\n", "normal")

        except Exception as e:
            self.log(f"Strings scan failed: {e}\n", "error")

        return None


if __name__ == "__main__":
    app = AHKDecompilerApp()
    app.mainloop()