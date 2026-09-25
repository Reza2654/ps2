# PowerScript 2 (`ps2`) VS Code Extension

Official syntax highlighting and language configuration extension for **PowerScript 2 (`.ps2`)** files.

## Features

- 🌈 Full TextMate grammar highlighting for `.ps2` and `.ps2bundle` files.
- 🔀 Highlight for pipeline operator `|>`, `=>`, and `->`.
- 🛡️ Highlighting for Zero-Trust `#manifest ... #endmanifest` directives and capabilities.
- 🧱 Highlighting for algebraic types (`Some`, `None`, `Ok`, `Err`).
- ⚡ Highlighting for all standard modules (`fs`, `net`, `json`, `str`, `sys`, `path`, `time`, `table`, `math`).
- 💬 Comment folding and auto-closing brackets/quotes.

## How to Install Locally

Copy the `extensions/vscode` folder into your VS Code extensions directory:
- **Windows**: `%USERPROFILE%\.vscode\extensions\ps2-vscode`
- **Linux / macOS**: `~/.vscode/extensions/ps2-vscode`

Or package it with `vsce package` and run:
```bash
code --install-extension ps2-vscode-0.1.0.vsix
```
