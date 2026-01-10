# Mini AV Engine

Mini AV Engine is a **client–server security research project** consisting of a lightweight C++ implant and a Flask-based server.
The system is designed to **detect known malicious indicators** (memory byte patterns and file hashes) and **report alerts securely**
to a centralized monitoring panel over HTTPS.

> ⚠️ **Disclaimer**
> This project is intended for **educational, defensive security, and research purposes only**.
> It must only be deployed on systems where you have **explicit authorization**.

---

## Architecture Overview

```
+------------------+        HTTPS        +----------------------+
|      Implant     |  <----------------> |        Server        |
|   (C++ / WinAPI) |                    |  (Flask / Python)    |
+------------------+                    +----------------------+
        |                                              |
        |                                              |
 Memory scanning                               Indicator storage
 File hash scanning                            Alert aggregation
 Process inspection                            Admin monitoring UI
```

---

## Components

### Implant (C++)

The implant is a native Windows application written entirely in C++ using WinAPI.

**Responsibilities:**
- Enumerate running processes
- Inspect process memory for known malicious byte patterns
- Scan files and compute SHA-256 hashes
- Compare hashes against known malicious indicators
- Report detections to the server over **HTTPS**
- Operate without external runtime dependencies

**Key characteristics:**
- No third-party runtime requirements
- HTTPS-only communication
- Minimal footprint
- Designed for controlled environments

---

### Server (Flask / Python)

The server acts as the central coordination and monitoring component.

**Responsibilities:**
- Store detection indicators
- Receive alerts from implants
- Provide an administrative monitoring interface
- Manage implant registration and status
- Serve indicator data to implants securely

---

## Indicator Types

### Binary Indicators (`.bin`)
- Contain raw byte sequences
- Used for detecting known malicious code patterns in process memory
- Loaded and distributed by the server
- Compared directly against memory regions by implants

### Hash Indicators (`.txt`)
- One SHA-256 hash per line
- Used to detect known malicious files on disk
- Simple, deterministic file integrity checks

---

## Communication

- **Protocol:** HTTPS (TLS-encrypted)
- **Format:** JSON
- **Authentication:** Implant UUID-based identification
- **Direction:**
  - Implant → Server: alerts, telemetry
  - Server → Implant: indicator updates

No plaintext communication is used.

---

## Admin Panel

The server includes an administrative interface used to:

- Monitor connected implants
- View detection alerts
- Inspect detected processes and files
- Track implant status (online/offline)
- Review indicator matches

---

## Project Structure (High-Level)

```
Mini-AV-Engine/
├── Implant/
│   ├── src/
│   ├── include/
│   └── build/
│
├── Server/
│   ├── src/
│   ├── indicators/
│   │   ├── binaries/
│   │   └── hashes/
│   ├── templates/
│   └── static/
│
└── README.md
```

---

## Security Notes

- This project is **not a replacement** for a production antivirus solution
- Indicators are signature-based and do not provide heuristic or behavioral analysis
- HTTPS must be correctly configured before deployment
- Always test in isolated or authorized environments

---

## License

This project is provided for **educational and research use only**.
No warranty is provided. The author assumes no responsibility for misuse.

---

## Author

Toko Tskhadiashvili
