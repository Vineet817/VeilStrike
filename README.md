# VeilStrike

🛡️ **VeilStrike** is an autonomous security reconnaissance and vulnerability scanning tool written in Rust.  
It discovers subdomains, resolves DNS, performs full port scans, and lays the groundwork for vulnerability detection — built for speed and scalability.

---

## 🚀 Features

- 🌐 **Subdomain Discovery**  
  Resolve active subdomains using DNS resolution against custom wordlists.

- 🔎 **Full Port Scanning (TCP)**  
  Async scanning from port `1` to `65535` on all resolved IPs using `tokio` concurrency.

- 🗂️ **Output Structure**  
  - `output/recon_output.csv`: Subdomains and their IPs
  - `ports/<ip>.txt`: List of open TCP ports per IP

- ⚙️ **Efficient Concurrency**  
  Smart use of `tokio::Semaphore` to control DNS, HTTP, and port scan concurrency.

- 🧱 **Modular Design**  
  Components split across recon, scanning, utils, and future-ready fuzzing modules.

---

## ⚙️ Usage

Build and run the scanner with a target domain or IP:

```bash
cargo run -- --url https://example.com
```
### 🧭 Available Flags

| Flag     | Description                                         |
|----------|-----------------------------------------------------|
| `--url`  | Target domain (e.g. `https://example.com`)          |
| `--ip`   | Target IP address                                   |
| `--repo` | Local codebase path (for future static analysis)    |

---

### 📂 Output

- `output/recon_output.csv`  
  Contains valid subdomains and their resolved IPs.

- `ports/<ip>.txt`  
  Individual text files storing open TCP ports per IP address found during recon.

---

### 🔧 Requirements

- **Rust 1.74+**
- **Internet access** for DNS queries and TCP scans
- ✅ Works on **Linux/macOS**  
- ⚠️ Windows is supported with minor adjustments (file paths, permissions)
