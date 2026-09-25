# Timeline — Payload Extraction Investigation

## Investigation Timeline

This timeline reconstructs the major artifact creation, extraction, analysis, and telemetry-review activities performed during Day 87.

The timeline is based on the observed PowerShell activity, filesystem metadata, archive information, and endpoint telemetry available during the investigation.

---

## 25 September 2026

### 06:57 — Investigation Workspace Created

The primary investigation directory was created:

```text
C:\PayloadExtractionLab
```

Subdirectories were established for:

```text
Evidence
Sample
Extracted
```

The workspace provided separate locations for the original sample, extracted artifacts, and investigation evidence.

---

### 06:57 — Host Baseline Collection

The investigation collected basic system information using:

```powershell
Get-CimInstance Win32_ComputerSystem
```

and:

```powershell
Get-CimInstance Win32_OperatingSystem
```

The investigation timestamp was also recorded.

This established the initial host context for the investigation.

---

### 06:59:08 — Benign Payload Created

The controlled payload was created at:

```text
C:\PayloadExtractionLab\Sample\payload.txt
```

Observed metadata:

```text
Length:
30 bytes

CreationTime:
25-09-2026 06:59:08

LastWriteTime:
25-09-2026 06:59:08
```

Content:

```text
BENIGN DFIR PAYLOAD - LAB 87
```

The payload was intentionally benign and was created specifically for the DFIR exercise.

---

### 07:04:50 — Payload Last Write Timestamp

The extracted payload later showed:

```text
LastWriteTime:
25-09-2026 07:04:50
```

This timestamp was recorded as filesystem metadata.

It should not be independently interpreted as proof of suspicious activity.

---

### 07:04:51 — Archive Created

The controlled payload was packaged into:

```text
C:\PayloadExtractionLab\Sample\payload-package.zip
```

Observed metadata:

```text
Length:
152 bytes

CreationTime:
25-09-2026 07:04:51

LastWriteTime:
25-09-2026 07:04:51
```

---

### 07:04 — Original Archive SHA256 Calculated

The SHA256 hash of the original archive was calculated.

```text
DC57D228EBA668067633E9B4C7681FC0AEF493F192B4A96E764A167A24FAEB02
```

This established an integrity reference for the original archive.

---

### 07:04 — Archive Contents Inspected

The archive was inspected before extraction.

Contained artifact:

```text
payload.txt
```

The archive structure was reviewed before continuing with payload extraction.

---

### 07:08:07 — Extracted Payload Metadata Observed

The extracted artifact was:

```text
C:\PayloadExtractionLab\Extracted\payload.txt
```

Observed metadata:

```text
Length:
30 bytes

CreationTime:
25-09-2026 07:08:07

LastWriteTime:
25-09-2026 07:04:50
```

The difference between filesystem timestamps was recorded as metadata rather than automatically interpreted as malicious behavior.

---

### 07:09:49 — Extracted Payload Last Access Timestamp

The extracted payload showed:

```text
LastAccessTime:
25-09-2026 07:09:49
```

This was retained as part of the artifact metadata.

---

### After Extraction — Payload Hashing

The extracted payload was hashed using multiple algorithms.

### MD5

```text
2ED45ADBCBE71DE32088536B9B8D5C3E
```

### SHA1

```text
AF66AF5581D0C55D45693451B31C3348D58F256D
```

### SHA256

```text
C5D5F3324F3A41774D09AD6D1C831A7A04D818865DFE174EA95A51EC73268A3A
```

The SHA256 hash was used as the primary integrity identifier for the extracted payload.

---

### Payload Content Analysis

The extracted payload was read:

```text
BENIGN DFIR PAYLOAD - LAB 87
```

The first bytes were inspected:

```text
42
45
4E
49
47
4E
20
44
46
49
52
20
50
41
59
4C
```

The bytes corresponded to the beginning of the known text payload.

The artifact did not present the typical `MZ` beginning associated with a Windows PE executable.

---

### Sysmon Event ID 11 Review

Sysmon Event ID 11 was queried for:

```text
PayloadExtractionLab
payload
```

No matching output was returned.

Assessment:

```text
No matching Sysmon file-creation event observed in the queried results.
```

This does not independently prove that no file creation event occurred.

---

### Sysmon Event ID 3 Review

Sysmon Event ID 3 was queried for:

```text
powershell
cmd.exe
payload
```

No matching output was returned.

Assessment:

```text
No matching Sysmon network event observed in the queried results.
```

No network activity from the benign payload was expected.

---

### Wazuh Telemetry Review

Wazuh telemetry was reviewed for related endpoint activity.

Observed process information included:

```text
Agent ID:
001

Agent Name:
DESKTOP-9MMM37V

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This established that PowerShell telemetry existed on the host.

The available information did not independently establish that the extracted payload was executed.

---

## Consolidated Timeline

```text
06:57
Lab workspace created
        ↓
06:57
Host baseline collected
        ↓
06:59:08
Benign payload created
        ↓
07:04:50
Payload LastWriteTime observed
        ↓
07:04:51
ZIP archive created
        ↓
07:04
Original archive SHA256 calculated
        ↓
07:04
Archive contents inspected
        ↓
Payload extracted
        ↓
07:08:07
Extracted payload CreationTime observed
        ↓
Payload hashes calculated
        ↓
Payload metadata examined
        ↓
Payload content inspected
        ↓
Payload bytes inspected
        ↓
07:09:49
Extracted payload LastAccessTime observed
        ↓
Sysmon Event ID 11 reviewed
        ↓
Sysmon Event ID 3 reviewed
        ↓
Wazuh telemetry reviewed
        ↓
Final assessment documented
```

---

## Timeline Interpretation

The timeline demonstrates the complete investigation workflow from artifact creation through extraction and analysis.

The available evidence establishes that:

- A controlled payload was created.
- The payload was packaged into a ZIP archive.
- The archive was hashed.
- The archive was inspected.
- The payload was extracted.
- The extracted payload was hashed.
- Metadata and content were examined.
- Sysmon telemetry was queried.
- Wazuh telemetry was reviewed.

The timeline does not establish malicious execution or compromise.

The appropriate interpretation is:

```text
Artifact Created
        ↓
Artifact Packaged
        ↓
Artifact Extracted
        ↓
Artifact Analyzed
        ↓
Execution Not Established
        ↓
Network Activity Not Observed
        ↓
Benign Controlled Lab Artifact
```

---

## Timeline Caveats

Filesystem timestamps should not be treated as a complete forensic timeline by themselves.

A stronger real-world investigation would correlate:

- Filesystem timestamps
- Process creation events
- PowerShell command lines
- Parent-child process relationships
- Sysmon file events
- Network connections
- Wazuh alerts
- User activity
- Archive creation and extraction events
- File hashes

The objective is to build a timeline from multiple independent evidence sources rather than relying on a single timestamp or artifact.
