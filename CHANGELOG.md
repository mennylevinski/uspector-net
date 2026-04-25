# Changelog
All notable changes to **Uspector Network Scanner** are documented in this file.

---

## [1.5.0] – 2026-04-25 Latest
### Added
- Added a branded icon to the executable (EXE)
- Enhanced real-time detection of short-lived TCP/HTTPS connections
- Introduced pseudo-flow tracking for UDP traffic using socket observation
- Reduces noise by applying TTL-based deduplication for repeated UDP activity

---

## [1.4.0] – 2026-04-05
### Added
- Added a basic Traffic Inspection feature as option 3 (Beta)
- Real-time monitoring of active TCP connections for selected ports

---

## [1.3.0] – 2026-03-20
### Added
- Name changed to "Uspector Network Scanner"
- More common ports added to the scanning list (43 total)

### Fixed
- Adjusted default worker threads for better stability

---

## [1.2.0] – 2026-02-23

### Added
- Essential stability optimizations for LAN detection mode

### Fixed
- Fixed ARP table tracing issue, devices are now detected correctly

---

## [1.1.0] – 2026-02-17

### Added
- Enhanced and balanced Windows 11 LAN scanning
- Optimized custom IP range scanning engine
- Proper handling of APIPA addresses (169.254.0.0/16)
- Enhanced subnet detection for Wi-Fi adapters
- Integrated `psutil` for improved network interface detection

### Fixed
- Resolved UnboundLocalError for local variable in test_print()
- Reduced excessive memory usage during concurrent _ping scans
- Fixed TCP alive check causing false positives on Windows 11
- Corrected MAC address parsing from ARP tables

---

## [1.0.0] – 2026-02-04 

### Initial Public Release
