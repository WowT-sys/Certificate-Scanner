# Certificate Scanner

A **high-performance PowerShell script** to scan directories for signed executables, validate certificates, and check expiration dates. Optimized for speed with parallel processing, caching, and smart filtering. Generates detailed CSV and HTML reports.

---

## Features

- **Certificate Validation**: Detect expired or soon-to-expire certificates.
- **Performance Optimizations**: Parallel processing, caching, and smart file filtering.
- **Customizable**: Supports multiple file types, directory exclusions, and depth limits.
- **Reporting**: Export results to CSV and HTML.
- **Integrity Checks**: Optional SHA256 hash calculation.

---

## Requirements

- **PowerShell**: Version 5.1+ (PowerShell Core 7+ recommended).
- **Permissions**: Admin rights may be required for certain directories.

---

## Usage

### Basic Scan
```powershell
.\Certfinder.ps1 -dir "C:\Program Files"
```

### Fast Mode
```powershell
.\Certfinder.ps1 -dir "C:\Program Files" -fast
```

### Export Results
```powershell
.\Certfinder.ps1 -dir "C:\Program Files" -csv -html
```

### Show Expired Certificates
```powershell
.\Certfinder.ps1 -dir "C:\Program Files" -expired
```

### Advanced Example
```powershell
.\Certfinder.ps1 -dir "C:\Program Files" -ext ".exe", ".dll" -exclude "Temp" -maxFiles 5000
```

---

## Parameters

| Parameter       | Description                                   | Default Value |
|------------------|-----------------------------------------------|---------------|
| `-dir`          | Directory to scan (required).                 | None          |
| `-ext`          | File extensions to scan.                     | Common types  |
| `-thresh`       | Days before expiration to flag as warning.    | 30            |
| `-csv`          | Export results to CSV.                       | Disabled      |
| `-html`         | Export results to HTML.                      | Disabled      |
| `-expired`      | Show only expired/expiring certificates.      | Disabled      |
| `-fast`         | Enable all performance optimizations.         | Disabled      |
| `-signedOnly`   | Scan only files likely to be signed.          | Disabled      |
| `-maxFiles`     | Limit the number of files to process.         | Unlimited     |
| `-threads`      | Number of parallel threads.                  | Auto-detected |

---

## Output

- **Console**: Summary of scanned files, valid/expired certificates, and unsigned files.
- **CSV/HTML**: Detailed reports with file paths, certificate details, and expiration status.

---

## Example Output

### HTML Output
![Screenshot](https://github.com/user-attachments/assets/3eae05aa-820a-4f07-b838-26344c9e8a71)


### Console
```plaintext
=== SUMMARY ===
Total Files: 1200
Valid Certificates: 1150
Expired Certificates: 20
Expiring Soon: 30
Unsigned Files: 50
```
---
