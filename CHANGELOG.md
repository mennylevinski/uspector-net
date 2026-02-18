# Changelog

## [1.1.0] – 2026-02-17 – Latest

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

### Changed
- Version number updated from `1.0.0` → `1.1.0`
- Default max workers reduced for safer Windows 11 execution
- Improved handling of multiple interfaces (Ethernet & Wi-Fi)

---

## [1.0.0] – 2026-02-04 

### Initial Public Release
