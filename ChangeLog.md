# ET5.5 Change Log

This changelog documents the evolution of the Evil Twin Wi-Fi Attack Suite (ET5.5) throughout the session, reflecting enhancements, bug fixes, and new features added iteratively. The development spanned from an initial basic implementation to a fully-featured toolset by 03:37 PM PST, Friday, January 02, 2026.

## Version History

### Initial Version (Baseline)
- **Date**: Prior to session start
- **Description**: Initial concept with basic Evil Twin AP setup, deauthentication attack, beacon spam, logging, and data saving (txt, json, yaml, pdf).
- **Features**:
  - TUI using curses for navigation.
  - Evil Twin AP with captive portal.
  - Deauth attack using Scapy.
  - Beacon spam functionality.
  - Logging to `evil_twin.log`.
  - Data export in multiple formats.
- **Limitations**: Basic input validation, no advanced attacks, limited error handling.

### Version 2
- **Date**: Early in session
- **Description**: Added PMKID capture and Karma attack, improved input validation.
- **Changes**:
  - **New Features**:
    - PMKID capture using hcxdumptool.
    - Karma attack with airbase-ng.
  - **Improvements**:
    - Added `validate_ssid`, `validate_channel`, `validate_mac` functions.
    - Enhanced TUI with basic status indicators.
- **Issues**: Limited platform support, no cracking capability.

### Version 3
- **Date**: Mid-session
- **Description**: Integrated hashcat for PMKID cracking, improved error handling.
- **Changes**:
  - **New Features**:
    - `crack_pmkid()` function with hashcat integration.
    - Bettercap console support.
  - **Improvements**:
    - Robust error handling for subprocess calls.
    - Added tool check with `check_tool()`.
  - **Fixes**: Improved cleanup on exit with `atexit.register`.
- **Issues**: No WPA3 support, TUI navigation rudimentary.

### Version 4
- **Date**: Mid-to-late session
- **Description**: Added bettercap PMKID capture, enhanced TUI with status indicators.
- **Changes**:
  - **New Features**:
    - `bettercap_pmkid_capture()` for advanced PMKID/SAE capture.
  - **Improvements**:
    - TUI now shows monitor mode, AP status, and captured data counts.
    - Progress bars with tqdm for attacks.
    - Cross-platform checks for Linux, Termux, and limited Windows support.
- **Issues**: Number key handling in TUI inefficient, missing WPS/Dragonblood attacks.

### Version 5.0
- **Date**: Late session
- **Description**: Added WPA3 PMKID support, Wifite automation, optimized TUI navigation.
- **Changes**:
  - **New Features**:
    - WPA3 PMKID/SAE support in `pmkid_attack()` and `bettercap_pmkid_capture()`.
    - `run_wifite()` for automated Wi-Fi attacks.
  - **Improvements**:
    - Optimized TUI with arrow key navigation and number key selection (1-9).
    - Enhanced logging with detailed error messages.
    - Added platform-specific monitor mode handling.
- **Issues**: Multi-digit number input (10-19) not supported, incomplete attack suite.

### Version 5.5 (Final)
- **Date**: 03:37 PM PST, Friday, January 02, 2026
- **Description**: Added WPS Pixie Dust, Reaver WPS brute force, WPA3 Dragonblood attack, fixed TUI number key handling.
- **Changes**:
  - **New Features**:
    - `pixie_dust_attack()` using bully for WPS Pixie Dust.
    - `reaver_attack()` for WPS brute force.
    - `dragonblood_attack()` using dragonslayer for WPA3 invalid curve attack.
  - **Improvements**:
    - Fixed TUI number key handling to support multi-digit input (1-19) with buffer.
    - Added `randmac()` for random MAC generation in beacon spam.
    - Enhanced responsive progress bars with higher refresh rate.
    - Improved captive portal with basic HTML form.
    - Robust input validation and error messaging.
  - **Fixes**:
    - Corrected TUI navigation to handle multi-digit selections properly.
    - Ensured cleanup on exit includes all processes (dnsmasq, hostapd, airbase-ng).
- **Notes**: Final version integrates all previous features with full functionality for educational testing. Requires external tools installation as per README.

## Summary of Changes
- **Total Features Added**: 14 (Evil Twin, Deauth, Beacon Spam, PMKID, Karma, Cracking, Bettercap Console, Bettercap PMKID, Wifite, Pixie Dust, Reaver, Dragonblood, Data Saving, Logging).
- **Key Improvements**: TUI usability, cross-platform support, error handling, progress tracking.
- **Fixed Issues**: TUI navigation, cleanup, tool dependency checks.

This changelog reflects the collaborative development process, culminating in ET5.5 as a robust tool for Wi-Fi security testing by the session's end.
