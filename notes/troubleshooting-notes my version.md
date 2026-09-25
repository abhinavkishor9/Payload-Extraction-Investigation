# Troubleshooting Notes 

## 1. Extracted Payload Path Error

### Problem

The SHA256 command initially failed with:

```text
Cannot find path 'C:\PayloadExtractionLab\Extracted\payload.txt' because it does not exist.
```

The command was:

```powershell
$ExtractedPayload = "$ExtractedPath\payload.txt"

Get-FileHash `
    -Path $ExtractedPayload `
    -Algorithm SHA256 |
Format-List
```

### Cause

The variable pointed to the expected extracted payload:

```text
C:\PayloadExtractionLab\Extracted\payload.txt
```

but the file did not exist at that location at the time the command was executed.

The hash operation itself was not the problem.

The investigation sequence had reached the hashing stage before confirming that the extraction step had successfully created the file.

### Resolution

First verify the archive:

```powershell
Test-Path $Archive
```

Then extract it:

```powershell
Expand-Archive `
    -Path $Archive `
    -DestinationPath $ExtractedPath `
    -Force
```

Verify the extraction:

```powershell
Get-ChildItem $ExtractedPath -Recurse -Force |
Select-Object FullName, Length, CreationTime, LastWriteTime
```

Then define the payload path:

```powershell
$ExtractedPayload = "$ExtractedPath\payload.txt"
```

Finally calculate the hash:

```powershell
Get-FileHash `
    -Path $ExtractedPayload `
    -Algorithm SHA256 |
Format-List
```

### Lesson

Before performing file analysis, confirm that the expected artifact actually exists.

A useful troubleshooting sequence is:

```text
Variable
   ↓
Expected Path
   ↓
Test-Path
   ↓
Directory Listing
   ↓
Extraction
   ↓
File Verification
   ↓
Hash
```

---

## 2. Verify Variables After Starting a New PowerShell Session

PowerShell variables such as:

```powershell
$LabPath
$EvidencePath
$SamplePath
$ExtractedPath
$Archive
$ExtractedPayload
```

only exist in the current PowerShell session.

If PowerShell is closed or a new session is started, recreate them:

```powershell
$LabPath = "C:\PayloadExtractionLab"
$EvidencePath = "$LabPath\Evidence"
$SamplePath = "$LabPath\Sample"
$ExtractedPath = "$LabPath\Extracted"

$Archive = "$SamplePath\payload-package.zip"
$ExtractedPayload = "$ExtractedPath\payload.txt"
```

Then verify:

```powershell
$LabPath
$Archive
$ExtractedPayload
```

---

## 3. Confirm the Archive Exists Before Extraction

Use:

```powershell
Test-Path $Archive
```

Expected result:

```text
True
```

If the result is:

```text
False
```

inspect the sample directory:

```powershell
Get-ChildItem $SamplePath -Force
```

The expected archive is:

```text
payload-package.zip
```

---

## 4. Confirm the Extracted Directory

Check:

```powershell
Test-Path $ExtractedPath
```

If necessary:

```powershell
New-Item `
    -ItemType Directory `
    -Path $ExtractedPath `
    -Force
```

Then extract:

```powershell
Expand-Archive `
    -Path $Archive `
    -DestinationPath $ExtractedPath `
    -Force
```

---

## 5. Confirm the Extracted File

Use:

```powershell
Test-Path $ExtractedPayload
```

Expected:

```text
True
```

Then:

```powershell
Get-Item $ExtractedPayload
```

This verifies that the path resolves to an actual file.

---

## 6. Avoid Incorrect Variable Syntax

A previous command showed:

```powershell
ExtractedPayload = "ExtractedPath\payload.txt"
```

This is incorrect because PowerShell variables require `$`.

Correct:

```powershell
$ExtractedPayload = "$ExtractedPath\payload.txt"
```

Incorrect:

```powershell
ExtractedPayload = "ExtractedPath\payload.txt"
```

Also avoid replacing the variable reference with a literal path name such as:

```text
ExtractedPath\payload.txt
```

The variable must resolve to the actual directory:

```text
C:\PayloadExtractionLab\Extracted
```

---

## 7. Check the Current Working Directory

The PowerShell prompt showed:

```text
PS C:\Windows\System32>
```

This is not a problem because the lab commands use absolute paths.

For example:

```text
C:\PayloadExtractionLab
```

is independent of the current working directory.

You can check the current location with:

```powershell
Get-Location
```

---

## 8. Do Not Confuse Archive and Payload Hashes

The archive SHA256 was:

```text
DC57D228EBA668067633E9B4C7681FC0AEF493F192B4A96E764A167A24FAEB02
```

The extracted payload SHA256 was:

```text
C5D5F3324F3A41774D09AD6D1C831A7A04D818865DFE174EA95A51EC73268A3A
```

These values are expected to be different.

The first hash identifies the ZIP archive.

The second hash identifies the extracted payload.

They represent different file objects.

---

## 9. Sysmon Event ID 11 Returned No Results

The query was:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 11
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "PayloadExtractionLab|payload"
} |
Select-Object TimeCreated, Message
```

No output was returned.

This does not automatically mean that file creation did not occur.

Possible explanations include:

- Sysmon Event ID 11 is not enabled.
- The event was not collected.
- The event was outside the queried range.
- The event message did not contain the searched text.
- Telemetry was not available at the time.
- The relevant activity occurred through a mechanism not represented in the queried results.

A better investigation statement is:

```text
No matching Sysmon Event ID 11 result was observed in the queried data.
```

Avoid:

```text
No file creation occurred.
```

---

## 10. Sysmon Event ID 3 Returned No Results

The network query was:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "powershell|cmd.exe|payload"
} |
Select-Object TimeCreated, Message
```

No output was returned.

The correct interpretation is:

```text
No matching network event was observed in the queried Sysmon results.
```

It should not automatically be converted into:

```text
The system had no network activity.
```

---

## 11. PowerShell Telemetry Does Not Automatically Prove Payload Execution

Wazuh telemetry showed:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The presence of PowerShell activity alone does not establish that:

```text
payload.txt
```

was executed.

A stronger execution determination would require correlation between:

```text
PowerShell Process
+
Command Line
+
Timestamp
+
Payload Path
+
Parent Process
+
File Hash
```

Therefore:

```text
PowerShell Activity ≠ Payload Execution
```

---

## 12. Timestamp Differences

The extracted payload showed:

```text
CreationTime:
25-09-2026 07:08:07

LastWriteTime:
25-09-2026 07:04:50

LastAccessTime:
25-09-2026 07:09:49
```

These timestamps should not automatically be interpreted as evidence of attacker behavior.

Archive extraction and normal filesystem operations can affect file timestamps.

Timestamp analysis should therefore be correlated with:

- Process events
- Archive creation time
- Extraction time
- User activity
- Sysmon events
- Wazuh events
- Other endpoint artifacts

---

## 13. Hexadecimal Output

The first bytes of the payload were:

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

These correspond to:

```text
BENIGN DFIR PAYL
```

This is consistent with the known text payload.

For Windows PE analysis, analysts commonly look for:

```text
MZ
```

at the beginning of a file.

However, file signatures should be treated as an identification aid rather than the only method of determining file type.

---

