# Striker

**Striker** is a professional website vulnerability scanner for penetration testing.  
It performs multiple scans on a given target and generates clean reports (including HTML).  

> ⚠️ Use Striker only on websites you own or have **explicit written permission** to test. Unauthorized scanning is illegal.

---

## Features

- Interactive mode: step-by-step confirmation before scanning  
- Progress spinner while fetching data  
- Verbose / Debug mode (`--debug`)  
- Generates **HTML reports** (stored in `reports/`)  
- Multiple vulnerability checks:
  - Headers & SSL/TLS checks  
  - Open ports  
  - Subdomain enumeration  
  - Directory scanning  
  - Basic vulnerability signatures  
- Cross-platform: Windows, Linux, macOS  
- Easy setup with one command or helper script  

---

## Quick Start

Clone this repository:

```bash
git clone https://github.com/yourusername/striker.git
cd striker
pip install -r requirements.txt
python striker.py