# Advanced Security Scanner for Linux Systems

This repository contains a comprehensive set of security scanning tools and scripts designed to perform thorough security audits on Linux systems, with optimization for Ubuntu 24.

## Overview

The Advanced Security Scanner consists of two main scripts:

1. **InstallSecTools.sh** - Installs all required security tools and utilities
2. **AdvSecScan.sh** - Performs a comprehensive security scan using the installed tools

These scripts are designed to help identify security vulnerabilities, potential rootkits, malware, network exposures, and system misconfigurations.

## Features

- **Optimized Performance**: Automatically utilizes available CPU threads for improved scan performance
- **Comprehensive Coverage**: Scans for malware, rootkits, open ports, vulnerabilities, and more
- **DMZ-specific Checks**: Specialized checks for DMZ server configurations
- **Detailed Reports**: Generates both log files and formatted HTML reports
- **Visual Feedback**: Color-coded terminal output for improved readability

## Requirements

- Ubuntu or Debian-based Linux distribution (optimized for Ubuntu 24)
- Root/sudo privileges for installation and scanning
- Internet connection (for updating security definitions)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/AdvSecScan.git
   cd AdvSecScan
   ```

2. Make the scripts executable:
   ```
   chmod +x InstallSecTools.sh AdvSecScan.sh
   ```

3. Install the required security tools:
   ```
   sudo ./InstallSecTools.sh
   ```

   **Note**: Some tools may need to be installed manually if they fail to install through the script. Pay attention to the console output during installation for any error messages.

## Usage

After installing the security tools, run the main scanning script:

```
sudo ./AdvSecScan.sh
```

The scan will proceed automatically and provide status updates in the terminal. Depending on your system specifications and the amount of data being scanned, this process may take anywhere from a few minutes to over an hour.

## Understanding the Output

### Terminal Output

The terminal displays real-time progress information with color-coded messages:
- **Blue**: Section headers
- **Green**: Informational messages
- **Yellow**: Warnings or important notes
- **Red**: Error messages or critical findings

### Generated Reports

Two types of reports are generated in the `~/security_scans/` directory:

1. **Log File** (`security_scan_TIMESTAMP.log`): Detailed technical log of all scan activities
2. **HTML Report** (`security_report_TIMESTAMP.html`): User-friendly formatted report with color-coded findings

## Installed Tools

The `InstallSecTools.sh` script installs the following security tools:

### Network Security
- nmap - Network exploration and security auditing
- wireshark - Network protocol analyzer
- tcpdump - Command-line packet analyzer
- iptraf-ng - Interactive network monitor
- nload - Network traffic monitor
- portsentry - Port scan detection tool

### System Security
- ufw - Uncomplicated Firewall
- fail2ban - Intrusion prevention system
- logwatch - Log analyzer
- aide - Advanced Intrusion Detection Environment
- debsums - Verify installed package integrity
- auditd - System auditing

### Anti-Malware
- clamav - Antivirus engine
- rkhunter - Rootkit detection tool
- chkrootkit - Another rootkit detector

### System Monitoring
- htop - Interactive process viewer
- glances - System monitoring tool
- sysstat - System performance tools

### Additional Tools
- lynis - Security auditing tool
- tiger - Report system security vulnerabilities
- nikto - Web server scanner
- binwalk - Firmware analysis tool
- foremost - File recovery tool
- testdisk - Data recovery utility

## Troubleshooting

### Installation Issues

If you encounter issues installing specific tools via the installation script, you can try installing them manually:

```
sudo apt install PACKAGE_NAME
```

Common issues include repository availability or package name changes. Check the error message for details.

### Scan Performance

The scanning script is designed to optimize performance based on available CPU threads. On systems with limited resources, you might want to modify the thread allocation in the script to avoid excessive resource usage.

### False Positives

Security scanning tools may occasionally report false positives. Always verify findings before taking action, especially for rootkit and malware detections.

## Regular Scanning

For optimal security, it's recommended to:

1. Run the security scanner regularly (weekly or monthly)
2. Keep all security tools updated (`sudo apt update && sudo apt upgrade`)
3. Update virus and rootkit definitions regularly

## License

[Your chosen license]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
