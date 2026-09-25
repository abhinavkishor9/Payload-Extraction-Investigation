# Investigation Notes — Payload Extraction Investigation

## Investigation Overview

This investigation focused on extracting and analyzing a controlled payload stored inside a ZIP archive.

The objective was to practice the workflow a SOC/DFIR analyst could use when investigating an archived artifact without assuming that the presence of a payload automatically indicates malicious activity.

The investigation followed:

```text
Preserve
    ↓
Inspect
    ↓
Extract
    ↓
Hash
    ↓
Identify
    ↓
Correlate
    ↓
Assess
```

---

## 1. Investigation Environment

Investigation workspace:

```text
C:\PayloadExtractionLab
```

Directory structure:

```text
C:\PayloadExtractionLab
├── Evidence
├── Sample
│   ├── payload.txt
│   └── payload-package.zip
└── Extracted
    └── payload.txt
```

The separation between `Sample`, `Extracted`, and `Evidence` helped maintain a clear investigation structure.

---

## 2. Controlled Artifact Creation

A benign text payload was created:

```text
BENIGN DFIR PAYLOAD - LAB 87
```

Original path:

```text
C:\PayloadExtractionLab\Sample\payload.txt
```

Observed size:

```text
30 bytes
```

The content was verified before packaging.

This established a known-good baseline for the subsequent extraction and analysis steps.

---

## 3. Archive Creation

The payload was compressed into:

```text
C:\PayloadExtractionLab\Sample\payload-package.zip
```

Observed archive size:

```text
152 bytes
```

The archive was treated as the original artifact for the investigation.

---

## 4. Original Artifact Integrity

The original archive SHA256 was calculated before extraction.

```text
DC57D228EBA668067633E9B4C7681FC0AEF493F192B4A96E764A167A24FAEB02
```

This hash provides an integrity reference for the archive as it existed during the investigation.

---

## 5. Archive Inspection

The archive was inspected before extraction.

The contained artifact was:

```text
payload.txt
```

The archive was therefore not treated as malicious merely because it contained a file referred to as a payload.

The analyst first established what the archive actually contained.

---

## 6. Payload Extraction

The archive was extracted into:

```text
C:\PayloadExtractionLab\Extracted
```

The resulting payload was:

```text
C:\PayloadExtractionLab\Extracted\payload.txt
```

The extracted file was then independently analyzed.

---

## 7. Extracted Payload Hashing

Multiple cryptographic hashes were calculated.

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

The SHA256 value is the primary integrity identifier used for the extracted artifact.

The archive and payload hashes are different because they represent different file objects.

---

## 8. Metadata Analysis

The extracted file metadata showed:

```text
FullName:
C:\PayloadExtractionLab\Extracted\payload.txt

Length:
30 bytes

CreationTime:
25-09-2026 07:08:07

LastWriteTime:
25-09-2026 07:04:50

LastAccessTime:
25-09-2026 07:09:49
```

The timestamps were recorded as evidence.

They were not independently interpreted as proof of malicious activity because filesystem timestamps can be influenced by normal file operations and extraction behavior.

---

## 9. Content Analysis

The payload content was:

```text
BENIGN DFIR PAYLOAD - LAB 87
```

The file therefore contained readable text rather than executable code.

The beginning of the file was also examined at the byte level.

Observed bytes:

```text
42 45 4E 49 47 4E 20 44 46 49 52 20 50 41 59 4C
```

These bytes correspond to the beginning of the text:

```text
BENIGN DFIR PAYL
```

The artifact did not begin with the common `MZ` signature associated with Windows PE executables.

---

## 10. Execution Analysis

Execution evidence was investigated through endpoint telemetry.

The investigation considered:

- Sysmon Event ID 1
- PowerShell activity
- Command-line information
- Process relationships
- Payload-related process activity
- Wazuh telemetry

The available evidence did not establish that `payload.txt` was executed.

This distinction is important because a text file being extracted or accessed does not mean that code execution occurred.

Assessment:

```text
Execution Evidence: Not Established
```

---

## 11. Sysmon File Creation Analysis

Sysmon Event ID 11 was queried for:

```text
PayloadExtractionLab
```

and:

```text
payload
```

The query returned no matching output during the investigation.

This finding should be interpreted carefully.

It means:

```text
No matching Sysmon Event ID 11 result was observed in the queried data.
```

It does not prove:

```text
No file creation occurred.
```

Potential reasons for missing telemetry include event filtering, collection configuration, query scope, or the event not being generated.

---

## 12. Sysmon Network Analysis

Sysmon Event ID 3 was queried for:

```text
powershell
cmd.exe
payload
```

No matching output was returned.

The controlled payload was not expected to generate network traffic.

Assessment:

```text
Network Activity: Not Observed
```

The finding is limited to the queried telemetry.

---

## 13. Wazuh Correlation

Wazuh telemetry contained PowerShell process information for the host.

Observed information included:

```text
Agent ID:
001

Agent Name:
DESKTOP-9MMM37V

Process:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This confirms that PowerShell telemetry existed in the endpoint data.

However, the existence of a PowerShell event does not establish that the extracted payload was executed.

A stronger execution finding would require correlation with information such as:

```text
Timestamp
+
Command Line
+
Parent Process
+
Payload Path
+
Payload Hash
```

Therefore:

```text
PowerShell Activity ≠ Payload Execution
```

---

## 14. Timeline Reconstruction

The major investigative sequence was:

```text
Lab workspace created
        ↓
Host baseline collected
        ↓
Investigation time recorded
        ↓
Benign payload created
        ↓
Payload verified
        ↓
Archive created
        ↓
Archive SHA256 calculated
        ↓
Archive inspected
        ↓
Payload extracted
        ↓
Extracted payload hashes calculated
        ↓
Metadata collected
        ↓
Content inspected
        ↓
Raw bytes inspected
        ↓
Sysmon process/file/network telemetry reviewed
        ↓
Wazuh telemetry reviewed
        ↓
Timeline generated
        ↓
Final assessment documented
```

---

## 15. Evidence Assessment

| Evidence | Observation | Assessment |
|---|---|---|
| Archive | `payload-package.zip` | Controlled lab artifact |
| Archive SHA256 | `DC57D228...FAEB02` | Integrity reference |
| Extracted file | `payload.txt` | Controlled text artifact |
| Payload SHA256 | `C5D5F332...268A3A` | Integrity reference |
| Payload content | Benign text | Non-executable content |
| File metadata | Timestamps and 30-byte size | Contextual evidence |
| Sysmon Event ID 11 | No matching result | Not observed in queried data |
| Sysmon Event ID 3 | No matching result | Not observed in queried data |
| Wazuh | PowerShell telemetry present | Requires correlation |
| Payload execution | Not established | Insufficient evidence |
| Network activity | Not observed | No matching queried event |
| Final assessment | Controlled benign artifact | Supported by lab construction and evidence |

---

## 16. Investigation Limitations

The investigation has several limitations.

### Limited Artifact Type

The payload was intentionally a benign text file. Therefore, the lab does not demonstrate analysis of a real executable, DLL, script, or malicious archive.

### Limited Telemetry

The Sysmon queries did not return matching file creation or network events. This limits what can be concluded from endpoint telemetry.

### No Malware Execution

The payload was not intentionally executed. Therefore, the investigation focuses on extraction and evidence correlation rather than live malware behavior.

### Controlled Environment

The artifact was created locally as part of the laboratory exercise. It should not be treated as evidence of an actual compromise.

---

## 17. Final Assessment

The investigation successfully demonstrated extraction and analysis of a controlled payload.

The artifact was identified as:

```text
payload.txt
```

with SHA256:

```text
C5D5F3324F3A41774D09AD6D1C831A7A04D818865DFE174EA95A51EC73268A3A
```

The payload contained benign text and did not present evidence of executable content.

The available endpoint telemetry did not establish payload execution or network communication.

The appropriate assessment for this controlled investigation is:

```text
Benign Controlled Lab Artifact
```

The main DFIR lesson is that analysts should distinguish between:

```text
Artifact Discovery
Artifact Extraction
Artifact Access
Artifact Execution
Network Communication
Compromise
```

These are separate investigative questions and should not be treated as interchangeable.
