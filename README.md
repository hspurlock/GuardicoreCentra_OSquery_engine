## OSQuery-Compliance

A Python CLI application that uses osquery to assess DOD STIG (Security Technical Implementation Guide) and CIS Benchmark compliance for multiple operating systems.

## Overview

This application leverages osquery to perform security compliance checks based on Department of Defense (DoD) Security Technical Implementation Guides (STIGs) and Center for Internet Security (CIS) Benchmarks. It provides a command-line interface to run compliance checks and generate reports across different operating systems.

## Features

- Automated STIG and CIS Benchmark compliance checks using osquery
- Multi-OS support (Linux, Windows, macOS)
- Operating system auto-detection
- Command-line interface for running compliance checks
- Detailed reports for compliance findings
- Export functionality for audit purposes
- Custom query execution for advanced users

## Requirements

- Python 3.8+
- osquery installed on the target system
- Dependencies listed in requirements.txt

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Make the script executable:
   ```
   chmod +x osquery_compliance.py
   ```

## Usage

The application provides several commands:

### List available checks
```
python osquery_compliance.py list
```

### List available checks for a specific OS
```
python osquery_compliance.py list --os-type windows
```

### Run all compliance checks
```
python osquery_compliance.py run
```

### Run all compliance checks for a specific OS
```
python osquery_compliance.py run --os-type macos
```

### Run a specific check by ID
```
python osquery_compliance.py run --check-id V-220901
```

### Generate a compliance report
```
python osquery_compliance.py report --output compliance_report.txt
```

### Generate a compliance report for a specific OS
```
python osquery_compliance.py report --os-type windows --output windows_compliance_report.txt
```

### Run a custom osquery query
```
python osquery_compliance.py query "SELECT * FROM users WHERE uid = 0;"
```

## Structure

- `osquery_compliance.py`: Main CLI application
- `stig_checks/`: Directory containing STIG check definitions in YAML format
  - `linux/`: Linux-specific STIG and CIS checks
    - `account_security.yml`: Checks for account security settings
    - `filesystem_security.yml`: Checks for filesystem security settings
    - `network_security.yml`: Checks for network security settings
    - `dod_system_settings.yml`: DOD STIG system configuration checks
    - `dod_audit_logging.yml`: DOD STIG audit and logging checks
    - `dod_system_hardening.yml`: DOD STIG system hardening checks
    - `cis_auth_settings.yml`: CIS Benchmark authentication settings checks
    - `cis_services.yml`: CIS Benchmark service configuration checks
    - `cis_network_security.yml`: CIS Benchmark network security checks
    - `cis_filesystem_security.yml`: CIS Benchmark filesystem security checks
  - `windows/`: Windows-specific STIG and CIS checks
    - `windows_security.yml`: Basic Windows security configuration checks
    - `dod_account_policies.yml`: DOD STIG account policy checks
    - `dod_audit_policies.yml`: DOD STIG audit policy checks
    - `dod_network_security.yml`: DOD STIG network security checks
    - `dod_system_hardening.yml`: DOD STIG system hardening checks
    - `cis_security_settings.yml`: CIS benchmark security settings checks
    - `cis_system_security.yml`: CIS benchmark system security checks
  - `macos/`: macOS-specific STIG and CIS checks
    - `macos_security.yml`: macOS security configuration checks

## Compliance Coverage

### Linux Compliance Checks

The tool includes comprehensive coverage of both DOD STIGs and CIS Benchmarks for Linux systems:

#### DOD STIG Checks
- **Account Security**: Password policies, account restrictions, privilege management
- **Filesystem Security**: File permissions, ownership, SUID/SGID controls
- **Network Security**: Firewall configuration, network services, protocol security
- **System Settings**: SELinux/AppArmor, core dumps, ASLR, crypto policies
- **Audit & Logging**: Auditd configuration, audit rules for critical events
- **System Hardening**: Bootloader security, duplicate UIDs/GIDs, home directory security

#### CIS Benchmark Checks
- **Authentication Settings**: Password complexity, expiration, reuse limits
- **Services**: Unnecessary network services, insecure protocols
- **Network Security**: IP forwarding, packet redirects, TCP SYN cookies
- **Filesystem Security**: Sticky bits, umask settings, critical file permissions

### Windows Compliance Checks

Comprehensive Windows security checks based on DOD STIGs and CIS Benchmarks including:

#### DOD STIG Checks
- **Account Policies**: Password history, complexity, lockout settings
- **Audit Policies**: Comprehensive auditing of system events, logons, and security changes
- **Network Security**: NTLM settings, LAN Manager authentication, secure communications
- **System Hardening**: User Account Control, FIPS compliance, Data Execution Prevention

#### CIS Benchmark Checks
- **Security Settings**: Account status, interactive logon settings, machine inactivity limits
- **System Security**: Windows Firewall configuration, lock screen settings, automatic logon
- **Network Protection**: IP source routing, ICMP redirects, TCP/IP parameters

### macOS Compliance Checks

Basic macOS security checks including:
- Firewall configuration
- System Integrity Protection
- FileVault encryption
- Automatic login settings
- Gatekeeper

## Extending the Tool

### Adding Custom Checks

You can easily add your own custom STIG or CIS checks by creating new YAML files in the appropriate OS-specific directory:

1. Navigate to the appropriate OS directory (e.g., `stig_checks/linux/`).
2. Create a new YAML file or edit an existing one.
3. Follow this format for defining checks:

```yaml
---
checks:
  - id: "CUSTOM-001"
    title: "Custom security check"
    description: "Description of what this check verifies"
    severity: "high|medium|low"
    query: "Your osquery SQL query here"
    condition:
      type: "equals|not_equals|greater_than|less_than|contains"
      field: "count|specific_field"
      value: "expected_value"
```

### Supporting a New Operating System

To add support for a new operating system:

1. Create a new directory under `stig_checks/` for the OS (e.g., `stig_checks/freebsd/`).
2. Add YAML files with appropriate checks for that OS.
3. The tool will automatically detect and use these checks when run on that OS.

## Guardicore Centra Integration

This application includes integration with Guardicore Centra for enhanced security monitoring and threat detection:

### Guardicore Features

- **Real-time Threat Detection**: Correlate osquery compliance data with Guardicore Centra's threat detection capabilities
- **Network Visualization**: Map compliance issues to network segments and traffic flows
- **Micro-Segmentation**: Use compliance data to inform micro-segmentation policies
- **Incident Response**: Trigger automated responses based on compliance violations
- **Unified Dashboard**: View compliance status alongside security incidents in a single interface

### Using the Guardicore Integration

```
python osquery_compliance.py guardicore --connect
```

Connect to your Guardicore Centra instance:

```
python osquery_compliance.py guardicore --connect --api-key YOUR_API_KEY --server guardicore.example.com
```

Send compliance data to Guardicore:

```
python osquery_compliance.py run --export-guardicore
```

View compliance issues in Guardicore context:

```
python osquery_compliance.py guardicore --view-compliance
```

## Future Development

Planned enhancements for future releases:

- Remediation guidance for non-compliant checks
- Categorization and tagging of checks for custom profiles
- Compliance history tracking and trending
- Integration with security information and event management (SIEM) systems
- Web-based dashboard for visualizing compliance status
- Expanded checks for additional operating systems
- Enhanced Guardicore integration with bi-directional data flow

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
