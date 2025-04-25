# 🔐 Security Policy

## 📣 Reporting a Vulnerability

If you discover a security vulnerability in **passman**, **please _do not_ open a public issue!**

Instead, contact me privately at:

**📬 [saad.dev158@gmail.com]**  

Include the following:
- Description of the issue
- Steps to reproduce
- The exploit/PoC used (if applicable)
- Impact assessment (if known)

I aim to respond within **1 week**, but it is just me, so do not spam my email.

---

## 🔐 Security Practices

- AES-256-GCM for encryption of credentials and config
- Scrypt KDF for master password hashing (N=32768, r=8, p=1)
- HMAC-SHA256 for data integrity verification
- Persistent lockout system after failed login attempts
- Clipboard auto-clear with user-defined timeout
- `mlock`, zeroing, and garbage collection for in-memory data

---

## 🚫 Excluded from Scope

The following **do not** qualify as valid security issues:

- Social engineering attacks
- Physical access attacks
- Running the binary with elevated privileges on an untrusted host
- Vulnerabilities in dependencies that aren't exploitable in context
- Issues requiring root access that are already protected (e.g., master password rotation)

---

## 🛡️ Recommendations for Users

- Use a strong and unique master password
- Install only on trusted Linux systems (Debian, Ubuntu, Raspberry Pi)
- Keep Go and your OS up to date
- Set proper file permissions on all `passman` config and store files
- Run the app with `--secure` in non-interactive or scripted environments

---

## 🔍 Audits

No third-party audits have been performed yet.  
We welcome code reviews and community contributions. Contact us if you'd like to sponsor a review.

---
