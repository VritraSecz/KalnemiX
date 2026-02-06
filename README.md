<div align="center">

# ⚡ KalnemiX ⚡

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux-lightgrey.svg)](#compatibility)
[![Version](https://img.shields.io/badge/version-1.0.2-brightgreen.svg)](#overview)
[![Status](https://img.shields.io/badge/status-stable-success.svg)](#overview)
[![Maintained](https://img.shields.io/badge/maintained-yes-green.svg)](#contributing)
[![Stars](https://img.shields.io/github/stars/VritraSecz/KalnemiX?style=social)](https://github.com/VritraSecz/KalnemiX)
[![Forks](https://img.shields.io/github/forks/VritraSecz/KalnemiX?style=social)](https://github.com/VritraSecz/KalnemiX)
[![Issues](https://img.shields.io/github/issues/VritraSecz/KalnemiX)](https://github.com/VritraSecz/KalnemiX/issues)
[![Contributors](https://img.shields.io/github/contributors/VritraSecz/KalnemiX/graphs/contributors)](https://github.com/VritraSecz/KalnemiX/graphs/contributors)
[![Languages](https://img.shields.io/github/languages/count/VritraSecz/KalnemiX)](https://github.com/VritraSecz/KalnemiX)
[![Code Size](https://img.shields.io/github/languages/code-size/VritraSecz/KalnemiX)](https://github.com/VritraSecz/KalnemiX)

</div>

<div align="center">
  <h3>⚡ VritraSec OSINT & Reconnaissance Toolkit ⚡</h3>
  <p>Security-first, privacy-focused tooling for real-world reconnaissance workflows.</p>
  <p><strong>Professional-grade OSINT and reconnaissance framework for cybersecurity professionals, penetration testers, and security researchers.</strong></p>
</div>

---

## 🎉 What's New in v1.0.2

### 🚀 Major Upgrade: Complete Rewrite & Professional Enhancement

KalnemiX v1.0.2 represents a complete transformation from the previous version, with significant architectural improvements, new features, and a professional-grade codebase.

#### ✨ Major Improvements

**🔧 Full CLI Support (NEW!)**
- Complete command-line interface with `argparse` for automation and scripting
- All modules accessible via CLI flags (e.g., `--whois`, `--subdomain-passive`)
- No more password protection - streamlined access for professional use
- Help system with `-h/--help`, version with `-v/--version`, and about with `-a/--about`

```bash
# Direct CLI usage - no interactive prompts needed!
python kalnemix.py --whois example.com
python kalnemix.py --subdomain-passive example.com
python kalnemix.py --tech https://example.com
```

**📌 New Reconnaissance Modules**
- **Passive Subdomain Discovery** (`--subdomain-passive`): Discovers subdomains from certificate transparency logs (crt.sh + certspotter) without direct target contact
- **Technology Fingerprinting** (`--tech`): Identifies web technologies, frameworks, CMS, and server software from headers and content analysis
- **HTTP Status Mapping** (`--status-map`): Maps common paths and reports HTTP response codes for quick attack surface visibility

**🏗️ Architectural Improvements**
- **Modular Code Structure**: Complete separation of concerns with dedicated modules
  - `core/kalnemix_features.py`: All feature implementations
  - `core/ui.py`: Terminal UI and color management
  - `core/banners.py`: Professional Rich library-based banners
- **Professional Terminal UI**: Upgraded from basic ANSI codes to Rich library
  - Beautiful, dynamic banners with multiple styles
  - Enhanced color palette and formatting
  - Better error messages and user feedback
- **Improved Error Handling**: Comprehensive exception handling and graceful failures
- **Code Quality**: Clean, maintainable, and well-organized codebase

**🎨 User Experience Enhancements**
- **Removed Password Protection**: Streamlined access for professional workflows
- **Better Input Validation**: Enhanced validation for CLI arguments and user inputs
- **Improved Output Formatting**: Clean, readable output with consistent styling
- **Signal Handling**: Proper Ctrl+C handling with graceful exit

**🔒 Security & Privacy**
- **Removed Deface Page Feature**: Removed potentially malicious functionality for ethical use
- **Privacy-First Design**: No data collection or tracking
- **Local Processing**: All operations performed locally

**⚡ Performance Optimizations**
- **Efficient Threading**: Optimized concurrent operations for faster scanning
- **Smart Timeouts**: Configurable timeouts prevent hanging operations
- **Resource Management**: Better memory and CPU usage

**📋 What Was Removed**
- ❌ Password protection system (streamlined for professional use)
- ❌ "Create Deface Page" feature (removed for ethical compliance)
- ❌ Output export/save functionality (removed for simplicity)
- ❌ Single-file monolithic structure (replaced with modular architecture)

**🔄 What Was Improved**
- ✅ All existing features enhanced with better error handling
- ✅ Subdomain discovery now supports three modes: Quick, Deep, and Passive
- ✅ Hash cracking with improved progress indication
- ✅ Port scanning with better output formatting
- ✅ All modules now support both interactive and CLI modes

---

## 📖 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Key Features](#-key-features)
- [🔧 Modules](#-modules)
  - [Network & Infrastructure Analysis](#network--infrastructure-analysis)
  - [Web Application Security](#web-application-security)
  - [Reconnaissance & Intelligence](#reconnaissance--intelligence)
  - [Security Testing Utilities](#security-testing-utilities)
- [🛠️ Installation](#️-installation)
  - [Linux Installation](#linux-installation)
  - [Termux Installation](#termux-installation)
  - [Dependencies](#dependencies)
- [🚀 Usage](#-usage)
  - [Interactive Mode](#interactive-mode)
  - [Command Line Usage](#command-line-usage)
  - [Usage Examples](#usage-examples)
- [📁 Folder Structure](#-folder-structure)
- [🧭 Compatibility](#-compatibility)
- [⚖️ Legal Disclaimer](#️-legal-disclaimer)
- [🐛 Troubleshooting](#-troubleshooting)
- [👤 Author](#-author)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🎯 Overview

KalnemiX is a comprehensive OSINT and reconnaissance toolkit built for fast discovery, clean output, and practical workflows across web targets. It offers both an interactive menu-driven interface and a fully scriptable CLI, making it ideal for both manual reconnaissance and automated security assessments.

Whether performing passive OSINT or deep active scanning, KalnemiX streamlines the initial phase of any penetration test or security audit. Built with Python 3.x, it integrates common system utilities (like Nmap, Whois, and Traceroute) with specialized Python libraries to provide a unified, professional-grade reconnaissance experience.

### 🎯 Use Cases

- **Penetration Testing**: Initial footprinting and reconnaissance phases
- **Bug Bounty Hunting**: Target enumeration and attack surface discovery
- **Security Audits**: Comprehensive network and web application analysis
- **OSINT Research**: Open source intelligence gathering and analysis
- **Digital Forensics**: Metadata extraction and information correlation

---

## ✨ Key Features

🔍 **20+ Specialized Reconnaissance Modules**  
🌐 **Network & Infrastructure Analysis** (IP, DNS, WHOIS, SSL, Ports, Traceroute)  
🔒 **Web Application Security Testing** (Headers, Robots, Directories, Tech Stack)  
🧭 **Subdomain Discovery** (Quick, Deep, Passive enumeration methods)  
🔐 **Network Analysis** (Port scanning, SSL scanning, OS fingerprinting)  
🧪 **Technology Fingerprinting** (Headers + content signal analysis)  
🧱 **HTTP Status Mapping** (Path visibility and response code analysis)  
🧩 **Dual Interface** (Interactive menu + Full CLI automation)  
🎨 **Professional Terminal UI** (Rich formatting, colored output, clean presentation)  
⚡ **Fast & Efficient** (Optimized for speed and reliability)

---

## 🔧 Modules

KalnemiX features 20+ specialized reconnaissance modules organized into functional categories:

### Network & Infrastructure Analysis

| Module | Description | Usage Example |
|--------|-------------|---------------|
| 🌐 **WHOIS Lookup** | Domain registration information and ownership details | `--whois example.com` |
| 🔍 **IP Lookup** | Comprehensive IP address intelligence including geolocation, ISP, ASN | `--ip 8.8.8.8` |
| 📋 **DNS Lookup** | DNS records analysis (A, AAAA, MX, TXT, NS, CNAME) | `--dns google.com` |
| 🔄 **Reverse IP Lookup** | Identify other domains hosted on the same server/IP address | `--reverse-ip 8.8.8.8` |
| 🔌 **Port Scanner** | Network port scanning and service detection | `--portscan example.com --endport 2000` |
| 🔐 **SSL Scanner** | SSL/TLS certificate analysis and security assessment | `--sslscan example.com` |
| 🛣️ **Traceroute** | Network path mapping to target destination | `--traceroute example.com` |
| 🌍 **Subnet Lookup** | Determine network block and associated IP ranges | `--subnet 192.168.1.1` |
| 🖥️ **OS Fingerprinting** | Attempt to determine target server's operating system | `--osfp example.com` |

### Web Application Security

| Module | Description | Usage Example |
|--------|-------------|---------------|
| 📄 **HTTP Headers** | HTTP security headers analysis and server information | `--httpheader https://example.com` |
| 🤖 **Robots Scanner** | Robots.txt file analysis and restricted path discovery | `--robots example.com` |
| 📁 **Directory Bruteforce** | Web directory and file discovery using wordlists | `--find-hidden example.com --wordlist core/dir_list.txt` |
| 🔗 **URL Extractor** | Extract URLs and links from web pages | `--extract-url example.com` |
| 🧪 **Tech Fingerprint** | Web technology stack identification (frameworks, CMS, servers) | `--tech https://example.com` |
| 🗺️ **HTTP Status Map** | Map common paths and report response codes | `--status-map example.com --scheme https --wordlist core/dir_list.txt` |

### Reconnaissance & Intelligence

| Module | Description | Usage Example |
|--------|-------------|---------------|
| 🌐 **Subdomain Discovery (Quick)** | Fast subdomain enumeration using common techniques | `--subdomain-quick example.com` |
| 🔍 **Subdomain Discovery (Deep)** | Comprehensive subdomain scanning with wordlist brute-forcing | `--subdomain-deep example.com --wordlist core/sublist.txt` |
| 🕵️ **Passive Subdomain Enumeration** | Discover subdomains from passive sources (crt.sh, certspotter) | `--subdomain-passive example.com` |

### Security Testing Utilities

| Module | Description | Usage Example |
|--------|-------------|---------------|
| 🔓 **Hash Cracking** | Password hash cracking with multiple algorithms | `--crackhash <hash> --hash-type md5 --wordlist core/crack_hash_pass.txt` |
| 📷 **Image Metadata** | Extract EXIF and metadata from image files | `--imgmeta /path/to/image.jpg` |
| 🐚 **Reverse Connection Template** | Generate reverse connection template for authorized lab use only | `--reverse-shell 192.0.2.1:4444` |

---

## 🛠️ Installation

### Linux Installation

```bash
# Clone the repository
git clone https://github.com/VritraSecz/KalnemiX.git

# Navigate to the project directory
cd KalnemiX

# Make scripts executable
chmod +x setup.sh kalnemix.py

# Run the setup script (installs dependencies)
bash setup.sh

# Run KalnemiX
python kalnemix.py
```

**Note**: If the setup script requires elevated privileges for package installation, run:
```bash
sudo bash setup.sh
```

### Termux Installation

```bash
# Update packages
pkg update -y
pkg upgrade -y

# Install required packages
pkg install git python -y

# Clone the repository
git clone https://github.com/VritraSecz/KalnemiX.git

# Navigate to the project directory
cd KalnemiX

# Make scripts executable
chmod +x setup.sh kalnemix.py

# Run the setup script
bash setup.sh

# Run KalnemiX
python kalnemix.py
```

### Dependencies

KalnemiX requires both system utilities and Python libraries:

#### System Dependencies

These are automatically installed by `setup.sh` on Debian-based systems:

```text
nmap          # Network scanning and port enumeration
sslscan       # SSL/TLS certificate analysis
exiftool      # Image metadata extraction
whois         # Domain registration lookup
traceroute    # Network path tracing
dnsutils      # DNS query utilities
```

#### Python Dependencies

Automatically installed via `pip` during setup:

```text
beautifulsoup4  # HTML parsing and web scraping
colorama        # Cross-platform terminal colors
dnspython       # DNS protocol implementation
html5lib        # HTML5 parser
python-nmap     # Nmap integration library
requests        # HTTP library for web requests
rich            # Enhanced terminal output and formatting
```

---

## 🚀 Usage

### Interactive Mode

Launch KalnemiX in interactive mode for a user-friendly menu experience:

```bash
python kalnemix.py
# or
python kalnemix.py --interactive
```

The interactive mode provides a numbered menu system where you can select any available module and provide target information through prompts.

### Command Line Usage

KalnemiX supports extensive command-line options for automation and scripting:

#### Basic Command Structure

```bash
python kalnemix.py [OPTIONS] <TARGET>
```

#### Getting Help

```bash
# Display help message
python kalnemix.py -h
# or
python kalnemix.py --help

# Show version
python kalnemix.py -v
# or
python kalnemix.py --version

# Show about information
python kalnemix.py -a
# or
python kalnemix.py --about
```

### Usage Examples

#### Network & Infrastructure Analysis

```bash
# WHOIS lookup
python kalnemix.py --whois example.com

# IP address intelligence
python kalnemix.py --ip 8.8.8.8

# DNS records lookup
python kalnemix.py --dns google.com

# Reverse IP lookup
python kalnemix.py --reverse-ip 1.1.1.1

# Traceroute
python kalnemix.py --traceroute example.com

# Port scanning (default end port: 1000)
python kalnemix.py --portscan example.com --endport 2000

# SSL certificate scan
python kalnemix.py --sslscan example.com

# Subnet information
python kalnemix.py --subnet 192.168.1.1

# OS fingerprinting (requires root)
python kalnemix.py --osfp example.com
```

#### Web Application Security

```bash
# HTTP headers analysis
python kalnemix.py --httpheader https://example.com

# Robots.txt analysis
python kalnemix.py --robots example.com

# Extract URLs from webpage
python kalnemix.py --extract-url example.com

# Find hidden files/directories
python kalnemix.py --find-hidden example.com --wordlist core/dir_list.txt

# Technology fingerprinting
python kalnemix.py --tech https://example.com

# HTTP status mapping
python kalnemix.py --status-map example.com --scheme https --wordlist core/dir_list.txt
```

#### Subdomain Discovery

```bash
# Quick subdomain scan
python kalnemix.py --subdomain-quick example.com

# Deep subdomain scan with wordlist
python kalnemix.py --subdomain-deep example.com --wordlist core/sublist.txt

# Passive subdomain discovery
python kalnemix.py --subdomain-passive example.com
```

#### Security Testing Utilities

```bash
# Crack password hash
python kalnemix.py --crackhash <hash> --hash-type md5 --wordlist core/crack_hash_pass.txt

# Extract image metadata
python kalnemix.py --imgmeta /path/to/image.jpg

# Generate reverse shell payload
python kalnemix.py --reverse-shell 192.0.2.1:4444
```

#### Supported Hash Types

The `--crackhash` module supports the following hash algorithms:
- `md5`
- `sha1`
- `sha224`
- `sha256`
- `sha384`
- `sha512`
- `sha3-224`
- `sha3-256`
- `sha3-384`
- `sha3-512`

---

## 📁 Folder Structure

```plaintext
KalnemiX/
│
├── 📄 kalnemix.py              # Main application file and CLI parser
├── 📄 setup.sh                 # Installation script for dependencies
├── 📄 LICENSE                  # MIT License file
├── 📄 README.md                # This file
│
└── 📁 core/                    # Core modules directory
    ├── 📄 __init__.py          # Module initialization
    ├── 📄 banners.py           # Custom rich terminal banners and UI elements
    ├── 📄 kalnemix_features.py # Primary functions (scanning, recon, utilities)
    ├── 📄 resolver.py          # DNS resolution logic
    ├── 📄 ui.py                # Terminal styling, color definitions, and prefixes
    ├── 📄 main_shell.php       # Reverse shell template
    ├── 📄 sublist.txt          # Subdomain wordlist
    ├── 📄 dir_list.txt         # Directory bruteforce wordlist
    └── 📄 crack_hash_pass.txt  # Password wordlist for hash cracking
```

---

## 🧭 Compatibility

KalnemiX is designed to work on the following platforms:

- ✅ **Linux** (Debian, Ubuntu, Kali Linux, and other Debian-based distributions)
- ✅ **Termux** (Android terminal emulator)

### System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux-based systems or Termux
- **Network**: Internet connection required for most modules
- **Privileges**: Some modules (like OS fingerprinting) may require root privileges

---

## ⚖️ Legal Disclaimer

**⚠️ IMPORTANT**: This tool is designed exclusively for **educational purposes** and **authorized security testing**.

### ✅ Authorized Uses

- Educational purposes and learning OSINT techniques
- Authorized penetration testing and security assessments
- Bug bounty programs with proper scope authorization
- Security research within legal boundaries
- Testing on systems you own or have explicit written permission to test

### ❌ Prohibited Uses

- Unauthorized scanning or testing of systems
- Illegal data collection or privacy violations
- Malicious reconnaissance or attack preparation
- Any activity violating local, state, or federal laws
- Unauthorized access to computer systems

**Users are solely responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction. The developers and contributors of KalnemiX assume no liability for misuse of this tool.**

---

## 🐛 Troubleshooting

### Common Issues and Solutions

| Issue | Potential Cause | Solution |
|:--- | :--- | :--- |
| `[x] Nmap not found!` | System dependency missing or not in PATH | Re-run `./setup.sh` with appropriate permissions (e.g., `sudo ./setup.sh`) |
| `ModuleNotFoundError: 'bs4'` | Python dependencies not installed | Ensure you use `python3` and reinstall: `pip install -r requirements.txt` or manually install packages |
| `Permission denied: ./kalnemix.py` | Execution permissions missing | Grant execution rights: `chmod +x kalnemix.py` |
| Output appears garbled | Terminal encoding or missing color support | Ensure your terminal supports UTF-8 and 256 colors |
| `OS fingerprinting requires root` | Insufficient privileges | Run with `sudo` for OS fingerprinting module |
| SSL scan fails | `sslscan` not installed | Install via: `sudo apt install sslscan` or run `./setup.sh` |
| Hash cracking slow | Large wordlist or complex hash | Use smaller wordlists for testing, or optimize wordlist selection |

### Error Handling

KalnemiX includes comprehensive error handling:
- Network timeouts are handled gracefully
- Missing dependencies are reported with clear messages
- Invalid inputs are validated before processing

### Getting Support

If you encounter issues not covered here:
1. Check the [GitHub Issues](https://github.com/VritraSecz/KalnemiX/issues) page
2. Ensure you're using the latest version
3. Verify all dependencies are correctly installed
4. Check that you have proper network connectivity

---

## 👤 Author

<div align="center">
  <h3>Alex</h3>
  <p><strong>Founder, Vritra Security Organization (VritraSec)</strong></p>
</div>

### 🌐 Connect With Us

+ [![Creator](https://img.shields.io/badge/Creator-Alex%20%7C%20VritraSec-%23f97316?style=for-the-badge&logo=github)](https://vritrasec.com)
+ [![Website](https://img.shields.io/badge/Website-vritrasec.com-%233b82f6?style=for-the-badge&logo=googlechrome&logoColor=white)](https://vritrasec.com)
+ [![GitHub](https://img.shields.io/badge/GitHub-VritraSecz-%231f2937?style=for-the-badge&logo=github&logoColor=white)](https://github.com/VritraSecz)
+ [![Instagram](https://img.shields.io/badge/Instagram-%40haxorlex-%23E1306C?style=for-the-badge&logo=instagram&logoColor=white)](https://instagram.com/haxorlex)
+ [![YouTube](https://img.shields.io/badge/YouTube-%40Technolex-%23FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@Technolex)
+ [![Telegram Channel](https://img.shields.io/badge/Channel-%40LinkCentralX-%2326A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/LinkCentralX)
+ [![Main Channel](https://img.shields.io/badge/Main%20Updates-%40VritraSec-%23096AEB?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/VritraSec)
+ [![Community](https://img.shields.io/badge/Community-%40VritraSecz-%230168C4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/VritraSecz)

### 👨‍💻 About the Developer

**Alex** is a cybersecurity researcher, developer, and automation-focused engineer. As the founder of Vritra Security Organization (VritraSec), he is dedicated to creating security-first, privacy-focused professional tools for developers, researchers, and power users.

**Mission**: Security-first, privacy-focused professional tools for developers, researchers, and power users

**Focus**: Cybersecurity utilities, OSINT frameworks, AI-assisted systems, automation tools, performance-oriented software

**Philosophy**: Transparent behavior, privacy by design, long-term stability and scalability, no bloat or misleading claims

**Engineering**: Clean logic, modular architecture, fault tolerance, efficiency across Linux, Termux, and cross-platform systems

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help improve KalnemiX:

1. 🍴 **Fork the repository**
2. 🌿 **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
3. 💾 **Commit your changes** (`git commit -m 'Add some AmazingFeature'`)
4. 📤 **Push to the branch** (`git push origin feature/AmazingFeature`)
5. 🔄 **Open a Pull Request**

### 💡 Ways to Contribute

- 🐛 **Report bugs and issues** - Help us identify and fix problems
- 💡 **Suggest new features or modules** - Share your ideas for improvements
- 📖 **Improve documentation** - Enhance clarity and completeness
- 🔧 **Add new reconnaissance modules** - Extend functionality
- 🧪 **Write tests** - Improve code reliability
- 🌍 **Translate to other languages** - Make KalnemiX accessible globally
- ⚡ **Performance optimizations** - Help make KalnemiX faster and more efficient

### Contribution Guidelines

- Keep changes aligned with VritraSec's security-first and privacy-focused principles
- Follow existing code style and formatting
- Add appropriate error handling and validation
- Update documentation for new features
- Test your changes thoroughly before submitting

---

## 📄 License

### 🏷️ MIT License - Permissions, Limitations & Requirements

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

#### ✅ Permissions

+ ![Commercial Use](https://img.shields.io/badge/✅%20Commercial%20Use-Allowed-brightgreen?style=flat-square&logo=dollar-sign&logoColor=white)
+ ![Modification](https://img.shields.io/badge/✅%20Modification-Allowed-brightgreen?style=flat-square&logo=edit&logoColor=white)
+ ![Distribution](https://img.shields.io/badge/✅%20Distribution-Allowed-brightgreen?style=flat-square&logo=share&logoColor=white)
+ ![Private Use](https://img.shields.io/badge/✅%20Private%20Use-Allowed-brightgreen?style=flat-square&logo=lock&logoColor=white)

#### ❌ Limitations

+ ![No Warranty](https://img.shields.io/badge/❌%20No%20Warranty-Provided-red?style=flat-square&logo=shield-x&logoColor=white)
+ ![No Liability](https://img.shields.io/badge/❌%20No%20Liability-Accepted-red?style=flat-square&logo=alert-triangle&logoColor=white)

#### ⚠️ Requirements

+ ![License Notice](https://img.shields.io/badge/⚠️%20License%20Notice-Required-orange?style=flat-square&logo=document-text&logoColor=white)

---

<div align="center">
  <p>⭐ If you found KalnemiX useful, please consider giving it a star!</p>
  <b>Made with ❤️ by <a href="https://github.com/VritraSecz">Alex Butler</a> | <a href="https://vritrasec.com">VritraSec</a></b>
  <p><strong>Security-first • Privacy-focused • Professional-grade</strong></p>
</div>
