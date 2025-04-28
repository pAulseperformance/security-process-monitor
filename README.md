# Security Process Monitor

A sophisticated bash script for monitoring and analyzing running processes on macOS systems for potential security risks.

## Overview

This script provides enhanced security monitoring by scanning running processes and flagging potential security concerns based on multiple risk factors:

- Resource usage (CPU, memory)
- Code signing status
- File age
- Network activity
- File permissions
- Execution path
- Parent-child process relationships
- Dynamic libraries
- Command arguments

## Features

- 🔍 **Multi-factor risk analysis**: Evaluates processes using 10+ security indicators
- 🚨 **Risk scoring**: Categorizes processes as LOW, MEDIUM, or HIGH risk
- 🔒 **Signature verification**: Checks code signatures and notarization status
- 🌐 **Network activity monitoring**: Identifies listening ports and established connections
- 📊 **Clear visual output**: Color-coded results with detailed security flags
- ⚙️ **Smart filtering**: Focus on suspicious processes while reducing false positives
- 🛡️ **Context awareness**: Understands legitimate development tools (e.g., VS Code processes)

## Usage

Run the script with:

```bash
./check_procs.sh
```

No additional parameters are required. The script automatically scans all running processes and displays potential security concerns.

## Output Explanation

The script provides a detailed output with the following columns:

- **PID**: Process ID
- **USER**: Username running the process
- **%CPU**: CPU usage percentage
- **%MEM**: Memory usage percentage
- **COMMAND**: Executable name (truncated)
- **RISK**: Risk level (LOW, MEDIUM, HIGH)
- **SIGNATURE**: Code signing status and authority
- **AGE**: Age of executable file
- **NETWORK**: Network activity information
- **SECURITY FLAGS**: Specific security concerns identified
- **PARENT**: Parent process chain

## Security Flags

The script uses the following flags to identify potential security concerns:

- **NEW_EXEC**: Executables created today
- **UNSIGNED**: Code not signed by a verified developer
- **ODD_PATH**: Applications running from non-standard locations
- **SETUID**: Process has elevated permissions
- **WORLD_W**: World-writable executable (potentially insecure)
- **ROOT!**: Application running as root from a non-system location
- **LISTENING**: Process has open listening ports
- **NET_CONN**: Process has established network connections
- **ODD_DYLIB**: Process uses non-standard dynamic libraries
- **SUSP_ARGS**: Process has potentially suspicious command arguments
- **VS_CODE**: Visual Studio Code related process (expected)
- **EXT_W**: World-writable file in extension directory (expected)
- **DEV_LIB**: Development libraries (expected in dev environment)

## Requirements

- macOS operating system
- Bash shell
- Standard macOS tools (ps, lsof, codesign, otool)

## License

[MIT License](LICENSE)