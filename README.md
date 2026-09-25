# Payload Extraction Investigation

## Overview

This lab demonstrates a basic DFIR workflow for investigating a potentially suspicious payload stored inside an archive.

The investigation uses a controlled and benign payload to simulate a situation where a SOC or DFIR analyst receives an archived artifact and needs to determine what it contains, preserve its integrity, extract the contents, identify the payload, and establish whether there is any supporting evidence of execution or network activity.

The investigation follows an evidence-first approach:

```text
Suspicious Artifact
        ↓
Locate / Preserve
        ↓
Extract Payload
        ↓
Hash
        ↓
Identify File Type
        ↓
Inspect Metadata
        ↓
Check Execution Evidence
        ↓
Correlate Endpoint Telemetry
        ↓
Build Timeline
        ↓
Final Assessment
```

The key principle of this lab is:

> Finding or extracting a payload does not automatically prove execution or compromise.

---

## Objectives

- Create a controlled DFIR investigation workspace.
- Establish a host and investigation-time baseline.
- Create and package a benign payload.
- Calculate the hash of the original archive.
- Inspect archive contents before extraction.
- Extract the payload into a controlled evidence directory.
- Calculate MD5, SHA1, and SHA256 hashes of the extracted payload.
- Examine payload metadata and content.
- Inspect raw file bytes for basic file-type identification.
- Search Sysmon for related process, file creation, and network activity.
- Correlate available Wazuh telemetry.
- Build an artifact timeline.
- Document findings and limitations.
- Make a final assessment based on evidence rather than assumptions.

---

## Lab Scenario

A SOC analyst receives an archived artifact that may contain a suspicious payload.

The analyst must determine:

- What the archive contains
- Whether the contained file can be extracted safely
- What type of file was extracted
- Whether the extracted file has suspicious characteristics
- Whether there is evidence that the payload was executed
- Whether the payload generated network activity
- Whether endpoint telemetry supports or contradicts the investigation
- What conclusions can be made from the available evidence

For this controlled lab, the payload is intentionally benign:

```text
BENIGN DFIR PAYLOAD - LAB 87
```

The purpose is to practice the investigation methodology without creating or executing malware.

---

## Environment

- Operating System: Windows
- PowerShell: 7.6.6
- Sysmon: Windows endpoint telemetry
- Wazuh: SIEM / endpoint telemetry
- Investigation Directory: `C:\PayloadExtractionLab`

### Directory Structure

```text
C:\PayloadExtractionLab
│
├── Evidence
│
├── Sample
│   ├── payload.txt
│   └── payload-package.zip
│
└── Extracted
    └── payload.txt
```

---

## Investigation Workflow

### 1. Establish the Investigation Workspace

The investigation workspace was created with separate directories for the original sample, extracted artifacts, and evidence.

```powershell
$LabPath = "C:\PayloadExtractionLab"
$EvidencePath = "$LabPath\Evidence"
$SamplePath = "$LabPath\Sample"
$ExtractedPath = "$LabPath\Extracted"
```

This separation helps maintain a clear distinction between the original artifact, extracted content, and investigation evidence.

---

### 2. Establish the Host Baseline

Basic host information and operating system information were collected before continuing with the investigation.

The investigation timestamp was also recorded.

This establishes contextual information that can later be used when reviewing endpoint telemetry and constructing the timeline.

---

### 3. Create the Controlled Payload

A benign text file was created:

```text
BENIGN DFIR PAYLOAD - LAB 87
```

The resulting file was:

```text
C:\PayloadExtractionLab\Sample\payload.txt
```

The original sample had a size of 30 bytes.

The file content was verified before it was packaged.

---

### 4. Create the Archive

The payload was compressed into:

```text
payload-package.zip
```

The resulting archive was stored under:

```text
C:\PayloadExtractionLab\Sample\
```

The archive was treated as the original artifact for the extraction investigation.

---

### 5. Preserve the Original Archive Hash

The SHA256 hash of the archive was calculated before extraction.

```text
DC57D228EBA668067633E9B4C7681FC0AEF493F192B4A96E764A167A24FAEB02
```

The hash provides an integrity reference for the original archive.

---

### 6. Inspect the Archive

The archive was inspected before extraction.

The archive contained the controlled payload:

```text
payload.txt
```

The archive size observed during the investigation was:

```text
152 bytes
```

No assumption was made that the presence of a payload inside an archive indicated malicious activity.

---

### 7. Extract the Payload

The archive was extracted into:

```text
C:\PayloadExtractionLab\Extracted\
```

The extracted artifact was:

```text
C:\PayloadExtractionLab\Extracted\payload.txt
```

The extraction process was verified by enumerating the destination directory.

---

### 8. Calculate Extracted Payload Hashes

The extracted payload was hashed using multiple algorithms for investigation practice.

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

The SHA256 value provides the primary modern integrity reference.

---

## Payload Metadata

The extracted payload was examined using PowerShell file metadata.

Observed values included:

```text
Path:
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

The timestamps were recorded as investigative evidence rather than being interpreted automatically as proof of attacker activity.

---

## Payload Content Analysis

The payload content was read directly:

```text
BENIGN DFIR PAYLOAD - LAB 87
```

The first bytes were also examined:

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

These hexadecimal values correspond to the beginning of the text content rather than a Windows PE executable signature.

For comparison, Windows PE files commonly begin with the `MZ` signature.

The payload in this controlled investigation was therefore identified as a text artifact rather than an executable payload.

---

## Endpoint Telemetry Analysis

### Sysmon Process Activity

Sysmon Event ID 1 was considered for identifying process creation associated with the payload.

The investigation searched for terms including:

```text
payload
powershell
cmd.exe
wscript
cscript
```

The objective was to determine whether a process appeared to execute or interact with the payload.

---

### Sysmon File Creation Activity

Sysmon Event ID 11 was queried for:

```text
PayloadExtractionLab
payload
```

No matching file-creation output was returned by the command during the investigation.

This should be documented as:

```text
Not observed in the queried Sysmon results
```

rather than interpreted as proof that no file creation occurred.

---

### Sysmon Network Activity

Sysmon Event ID 3 was queried for network activity associated with:

```text
powershell
cmd.exe
payload
```

No matching network-event output was returned by the query.

For this controlled benign payload, network communication was not expected.

The absence of matching output does not independently prove that the host had no network activity.

---

## Wazuh Correlation

Wazuh telemetry was reviewed for related endpoint activity.

The available telemetry included PowerShell process information associated with the lab host.

The observed Wazuh record included:

```text
Agent ID:
001

Agent:
DESKTOP-9MMM37V

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This demonstrates that PowerShell activity was present in the broader endpoint telemetry.

However, the presence of `powershell.exe` alone does not prove that the extracted payload was executed.

Correlation with command-line arguments, parent process information, timestamps, file activity, and other telemetry would be required to establish a direct execution relationship.

---

## Timeline

The investigation reconstructed the workflow as:

```text
25-09-2026
    ↓
Lab directories created
    ↓
Host baseline recorded
    ↓
Benign payload created
    ↓
Payload verified
    ↓
Archive created
    ↓
Original archive SHA256 calculated
    ↓
Archive inspected
    ↓
Payload extracted
    ↓
Extracted payload SHA256 / SHA1 / MD5 calculated
    ↓
Payload metadata examined
    ↓
Payload content and bytes inspected
    ↓
Sysmon file/process/network telemetry reviewed
    ↓
Wazuh telemetry reviewed
    ↓
Artifact timeline generated
    ↓
Final assessment documented
```

---

## Findings

### Artifact

```text
payload-package.zip
```

### Original Archive SHA256

```text
DC57D228EBA668067633E9B4C7681FC0AEF493F192B4A96E764A167A24FAEB02
```

### Extracted Payload

```text
payload.txt
```

### Extracted Payload SHA256

```text
C5D5F3324F3A41774D09AD6D1C831A7A04D818865DFE174EA95A51EC73268A3A
```

### Payload Type

```text
Benign text artifact
```

### Execution Evidence

```text
Not established
```

### Network Activity

```text
Not observed in the queried Sysmon results
```

### Wazuh Evidence

```text
PowerShell telemetry observed
```

### Final Assessment

```text
Benign controlled lab artifact
```

The assessment is based on the known construction of the lab artifact and the observed investigation results.

The available evidence does not establish that the extracted payload was executed or that it generated network communication.

---

## Key DFIR Lessons

### 1. Extraction is not execution

A file can be extracted without being executed.

```text
Extracted ≠ Executed
```

### 2. A hash establishes identity and integrity

Hashes allow an analyst to track and compare an artifact during an investigation.

```text
Archive SHA256
        ↓
Extraction
        ↓
Payload SHA256
```

The archive hash and extracted payload hash represent different artifacts and therefore should not be expected to match.

### 3. File existence is not proof of compromise

A suspicious filename, directory, archive, or extracted file should trigger investigation rather than an automatic compromise conclusion.

### 4. Telemetry must be correlated

A PowerShell event by itself does not prove that a particular payload was executed.

Useful correlation fields include:

- Timestamp
- Process image
- Command line
- Parent process
- User
- File path
- File hash
- Network destination
- Related Sysmon events
- SIEM alerts

### 5. Absence of telemetry has limitations

No matching Sysmon result may mean that:

- The event did not occur
- The event was not logged
- The event was outside the queried range
- The relevant telemetry was not collected
- The query did not match the event

Therefore:

```text
No telemetry ≠ No activity
```

---

## Evidence-First Approach

This lab follows the principle:

> Follow the evidence, not the assumption.

Each finding should be categorized according to what the available evidence actually supports.

```text
Confirmed
    ↓
Directly supported by evidence

Plausible
    ↓
Possible but not established

Unknown
    ↓
Insufficient telemetry or evidence

Not Observed
    ↓
No matching event found in the queried data
```

This approach prevents an analyst from turning an artifact into an unsupported compromise conclusion.

---

## Conclusion

This investigation demonstrated a controlled payload extraction workflow using PowerShell, file hashing, metadata analysis, basic file identification, Sysmon, and Wazuh telemetry. The benign payload was successfully extracted and identified as a text artifact, while the available telemetry did not establish payload execution or network activity. The primary DFIR lesson is that artifact extraction, file existence, and PowerShell activity must be correlated with execution and network evidence before drawing conclusions about compromise.
