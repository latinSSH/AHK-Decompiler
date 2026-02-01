# AHKDecompiler – Simple AutoHotkey .exe String Extractor

```
                                           __         __   __
                                          |  |.---.-.|  |_|__|.-----.
                                          |  ||  _  ||   _|  ||     |
                                          |__||___._||____|__||__|__|
```

Tiny tool that extracts readable strings from compiled AutoHotkey (.exe) files — especially useful for getting the original AHK source code or large chunks of it.

Just drag your .exe onto AHKDecompiler.exe (or run it from cmd with the file as argument) → it dumps all extracted strings to the console + saves them to desktop.

You can then copy-paste the output into ChatGPT, Deepseek, Grok, Claude, etc. and ask it to reconstruct / re-format the original AutoHotkey script.

**Important note**  
This works best on **non-obfuscated / non-encrypted** AutoHotkey v1/v2 executables compiled the standard way (most common case).  
If the script was compiled with `/NoDecompile`, password-protected, heavily obfuscated, compressed (UPX etc.), or uses mCode / binary blobs → results will be incomplete or garbage.  
Use only on files you have permission to analyze (your own scripts, recovery, research, etc.). Decompiling other people's protected tools may violate laws / ToS.

## Features

- Super simple: one exe, no install needed
- Extracts all human-readable strings (including most of the original AHK code in plain-text compiled exes)
- Saves output to desktop automatically
- Console output so you can see results instantly
- Built as standalone PyInstaller exe (source included — see below)

## Requirements

- **Windows** (tested on Win10/11 — should work on 7+)
- Nothing else — no Python needed to **run** the .exe
- Add `AHKDecompiler.exe` to your antivirus exclusions  
  → PyInstaller executables often get flagged as false-positive malware

## Installation / Get Started

### Option 1: Download the pre-built EXE (easiest)

1. Go to the repository main page
2. Download `AHKDecompiler.exe` from the releases or root folder
3. (Recommended) Add it to Windows Defender / antivirus exclusions right away
4. Done — just run it!

### Option 2: Use the source code (if you don't trust binaries)

1. Open the `source-code` folder
2. Make sure you have **Python 3.8+** installed
3. Double-click `start.bat`  
   → it installs dependencies (if needed) and runs the script
3. Done

## Usage

**Method 1 – Drag & Drop (easiest)**

1. Drag any `.exe` file (compiled AHK script) onto `AHKDecompiler.exe`
2. Wait a few seconds
3. Check:
   - Console shows the extracted strings
   - String appears on the desktop

**Method 2 – Command line**

```bash
AHKDecompiler.exe "C:\path\to\your\script.exe"
```

Or just run the exe without arguments → it will prompt for a file path.

**Then:**

- Open the desktop and the AHK script in notepad.
- Paste into ChatGPT / Grok / Deepseek with a prompt like:  
  > Here are strings extracted from a compiled AutoHotkey .exe. Please try to reconstruct the original .ahk script as best as you can, including hotkeys, labels, functions, and formatting:

## Tips & Troubleshooting

- **AV false positive?** → Very common with PyInstaller. Exclude the file/folder or use source + start.bat
- **Output looks like junk?** → Script probably uses encryption, #NoEnv tricks, or was compiled with protection. Tool can't magically decrypt protected code.
- **Very large exes?** → May take 10–30 seconds. Be patient.
- **No strings at all?** → Likely packed (UPX) or binary-only payload. Try unpacking first.
- **Want better decompilation?** → Paste output to a strong reasoning model (o1, Deepseek R1, etc.) and give it multiple attempts.

## Disclaimer

**This tool is for educational / recovery purposes only.**  
The author is not responsible for misuse, legal issues, antivirus flags, or broken exes.  
AutoHotkey compiled exes are **not** secure — anyone can extract strings with enough effort. Don't rely on compilation for protection.

Made with ♥ by latin · 2026
