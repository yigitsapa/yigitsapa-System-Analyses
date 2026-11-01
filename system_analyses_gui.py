#yigitsapa System Analyses Engine luncher.
from __future__ import annotations
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText
BASE_DIR = Path(__file__).resolve().parent
ENGINE = BASE_DIR / "system_analyses.py"
class SystemAnalysesGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("yigitsapa System Analyses")
        self.root.geometry("1040x720")
        self.root.minsize(760, 480)
        self.process: subprocess.Popen[str] | None = None
        self.events: queue.Queue[tuple[str, str | int]] = queue.Queue()
        self.reader_thread: threading.Thread | None = None
        self.closing = False
        self.mode = tk.StringVar(value="Quick")
        self.status = tk.StringVar(value="Ready — choose an analysis mode and press Start.")
        shell = ttk.Frame(root, padding=(14, 12, 14, 8))
        shell.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            shell,
            text="yigitsapa System Analyses Engine",
            font=("Segoe UI", 19, "bold"),
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 10))
        controls = ttk.Frame(shell)
        controls.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(controls, text="Analysis mode:").pack(side=tk.LEFT)
        mode_box = ttk.Combobox(
            controls, textvariable=self.mode,
            values=("Quick", "Standard", "Deep", "Diagnostics"),
            state="readonly", width=14,
        )
        mode_box.pack(side=tk.LEFT, padx=(8, 14))
        self.start_button = ttk.Button(controls, text="Start analysis", command=self.start_analysis)
        self.start_button.pack(side=tk.LEFT)
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(controls, text="Clear output", command=self.clear_output).pack(side=tk.RIGHT)
        self.output = ScrolledText(
            shell, wrap=tk.WORD, state=tk.DISABLED,
            font=("Consolas", 10), padx=10, pady=8,
            background="#101820", foreground="#e6edf3",
            insertbackground="#e6edf3",
        )
        self.output.pack(fill=tk.BOTH, expand=True)
        status_bar = ttk.Frame(shell, relief=tk.SUNKEN, padding=(8, 5))
        status_bar.pack(fill=tk.X, pady=(8, 0))
        self.status_label = ttk.Label(status_bar, textvariable=self.status, anchor="w")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", length=130)
        self.progress.pack(side=tk.RIGHT, padx=(8, 0))
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.append_output("yigitsapa System Analyses Engine\n")
        self.append_output("Ready. Select Quick, Standard, Deep, or Diagnostics and start an analysis.\n\n")
        self.root.after(100, self.process_events)
        self.root.after(350, self.start_analysis)
    def append_output(self, text: str) -> None:
        self.output.configure(state=tk.NORMAL)
        at_bottom = self.output.yview()[1] >= 0.985
        self.output.insert(tk.END, text)
        if at_bottom:
            self.output.see(tk.END)
        self.output.configure(state=tk.DISABLED)
    def clear_output(self) -> None:
        if self.process and self.process.poll() is None:
            messagebox.showinfo("Analysis running", "Stop the current analysis before clearing its output.")
            return
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.configure(state=tk.DISABLED)
        self.append_output("yigitsapa System Analyses Engine\n")
    def start_analysis(self) -> None:
        if self.process and self.process.poll() is None:
            return
        if not ENGINE.is_file():
            messagebox.showerror("Engine not found", f"The analyzer was not found:\n{ENGINE}")
            self.status.set("Error — analyzer script not found.")
            return
        selected = self.mode.get()
        args = {
            "Quick": ["--quick"],
            "Standard": [],
            "Deep": ["--deep"],
            "Diagnostics": ["--diagnostics"],
        }.get(selected, ["--quick"])
        interpreter = Path(sys.executable)
        if os.name == "nt" and interpreter.name.casefold() == "pythonw.exe":
            console_interpreter = interpreter.with_name("python.exe")
            if console_interpreter.is_file():
                interpreter = console_interpreter
        command = [str(interpreter), "-u", str(ENGINE), *args]
        self.append_output(f"\n{'=' * 72}\nStarting {selected.lower()} analysis...\n")
        self.append_output("Command: " + subprocess.list2cmdline(command) + "\n\n")
        self.status.set(f"Running {selected.lower()} analysis… output is streaming.")
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.progress.start(12)
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW
        try:
            self.process = subprocess.Popen(
                command,
                cwd=BASE_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
            )
        except (OSError, ValueError) as exc:
            self.finish_process(None, f"Could not start the analyzer: {exc}\n")
            return
        self.reader_thread = threading.Thread(target=self.read_process_output, args=(self.process,), daemon=True)
        self.reader_thread.start()
    def read_process_output(self, process: subprocess.Popen[str]) -> None:
        try:
            if process.stdout is not None:
                for line in iter(process.stdout.readline, ""):
                    self.events.put(("output", line))
        except (OSError, UnicodeError) as exc:
            self.events.put(("output", f"\n[GUI output reader warning: {exc}]\n"))
        finally:
            code = process.wait()
            self.events.put(("exit", code))
    def stop_analysis(self) -> None:
        if not self.process or self.process.poll() is not None:
            return
        self.status.set("Stopping analysis…")
        self.append_output("\nStop requested by the user.\n")
        try:
            self.process.terminate()
        except OSError as exc:
            self.append_output(f"Could not terminate the analyzer: {exc}\n")
    def process_events(self) -> None:
        if self.closing:
            return
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "output":
                    self.append_output(str(payload))
                elif kind == "exit":
                    self.finish_process(int(payload), None)
        except queue.Empty:
            pass
        self.root.after(100, self.process_events)
    def finish_process(self, return_code: int | None, error: str | None) -> None:
        if error:
            self.append_output(error)
        self.progress.stop()
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        if return_code is None:
            self.status.set("Could not start analysis.")
        elif return_code == 0:
            self.status.set("Completed successfully. Reports are saved in system_analyses_reports when enabled.")
            self.append_output("\nAnalysis process completed successfully.\n")
        elif return_code < 0:
            self.status.set(f"Analysis stopped (process signal/exit code {return_code}).")
            self.append_output(f"\nAnalysis process stopped (exit code {return_code}).\n")
        else:
            self.status.set(f"Analysis finished with exit code {return_code}.")
            self.append_output(f"\nAnalysis process finished with exit code {return_code}.\n")
        self.process = None

    def on_close(self) -> None:
        if self.process and self.process.poll() is None:
            if not messagebox.askyesno("Exit", "An analysis is still running. Stop it and close the GUI?"):
                return
            try:
                self.process.terminate()
            except OSError:
                pass
        self.closing = True
        self.root.destroy()
def main() -> int:
    root = tk.Tk()
    SystemAnalysesGUI(root)
    root.mainloop()
    return 0
if __name__ == "__main__":
    raise SystemExit(main())