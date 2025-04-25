# 🔐 passman

**passman** is a secure, terminal-based password manager written in Go. It stores credentials locally using AES-GCM encryption, Scrypt key derivation, and robust HMAC integrity checks. Designed for Linux systems, especially Raspberry Pi, Debian, and Ubuntu, `passman` combines strong cryptography with user-friendly terminal UI.

---

## 🚀 Features

- 🧠 Secure master password system (scrypt, AES-GCM, HMAC-SHA256)
- 🔐 Credential storage with encryption and metadata
- 📋 Clipboard auto-clear feature (default 30s)
- 🔄 Password rotation (auto-generated passwords with length control)
- 🔎 Searchable credential store
- 🧪 Password strength enforcement
- 🧾 First-run secure setup
- 👮 Root-only master password reset
- 🛡️ Lockout mechanism on multiple failed attempts
- 🎨 Terminal UI with colors, spinners, and clean layout

---

## 📦 Installation

### Prerequisites:
- Go 1.18+
- Linux (Debian, Ubuntu, Raspberry Pi preferred)
- `xclip` or `xsel` (for clipboard features)

### Build from source:

```bash
git clone https://github.com/yourusername/passman.git
cd passman
go build -o passman main.go
sudo ./passman  # As of now, only root my use the tool.
```

---

## 🛠️ Usage

```bash
sudo ./passman # As of now, only root may use the tool.
```

Interactive menu:

```
1. View all credentials
2. View specific credential
3. Add/update credential
4. Delete credential
5. Search credentials
6. Rotate password
7. Change master password (root only)
8. Help
9. About
0. Exit
```

Command-line options:

| Flag | Description |
|------|-------------|
| `--secure` | Suppress sensitive output |
| `--help` | Show help menu |
| `--version` | Show version info |
| `--search <term>` | Search credentials |
| `--rotate <service>` | Rotate password |
| `--length <n>` | Password length for generated passwords |
| `--clip-timeout <s>` | Clipboard clear timeout in seconds |

---

## 🧠 Security Model

- **Key Derivation:** Scrypt (N=32768, r=8, p=1)  
- **Encryption:** AES-256-GCM  
- **Integrity:** HMAC-SHA256  
- **Memory Protection:** `mlock`, zeroing, GC hints  
- **Persistent Lockout:** After repeated failures  
- **File Permissions:** Enforced config and data access  

> 🛡️ All sensitive data is zeroed in memory after use.

---

## 🔧 Config & Storage

Default paths:
- Config: `~/.config/passman/config.json`
- Store: `~/.config/passman/store.json`
- Log: `~/.config/passman/passman.log`
- Lockout: `~/.config/passman/lockout.json`

Runs use `/etc/passman/` and `/var/log/passman.log`.

---

## 🧑‍💻 Contributing

Pull requests, suggestions, and feature ideas are welcome!

- Clone the repo
- Use `go fmt` for code formatting
- Write tests where possible
- Keep security in mind for any features
- Any suggestions are more than open

---

## 📜 License

MIT License © SaadSaid158

---
