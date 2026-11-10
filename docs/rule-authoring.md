# ForensiQ Rule & Threat Detection Authoring Guide

This guide details how to author, test, and maintain deterministic detection rules and Indicators of Compromise (IOCs) in ForensiQ.

---

## 1. Overview of the Detection Engine

ForensiQ employs a hybrid threat detection model:
1. **Deterministic Rule Engine**: Matches structured normalized evidence records against YAML-defined rules based on MITRE ATT&CK techniques.
2. **IOC Matcher**: Compares source/destination IP addresses, file hashes, and domain names against known threat indicators.
3. **Unsupervised ML Engine**: Complements deterministic rules by flagging statistical outliers and behavioral anomalies via Isolation Forests.

Deterministic rules reside in `data/rules/default_rules.yaml`.

---

## 2. Rule Schema Specification

Every rule is defined as an entry under the top-level `rules:` list in YAML.

### Field Definitions

| Field | Required | Type | Description |
| :--- | :--- | :--- | :--- |
| `id` | Yes | String | Unique rule identifier (e.g., `PROC-001`, `AUTH-SEQ-002`, `NET-003`). |
| `name` | Yes | String | Clear, descriptive name of the threat detection. |
| `description` | Yes | String | Detailed explanation of the adversary technique and forensic significance. |
| `severity` | Yes | String | Severity rating: `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `category` | Yes | String | MITRE ATT&CK tactic category (e.g., `INITIAL_ACCESS`, `EXECUTION`, `CREDENTIAL_ACCESS`, `LATERAL_MOVEMENT`, `EXFILTRATION`). |
| `conditions` | Yes | Object | Mapping of CES field names to matcher criteria. |

---

## 3. Condition Matchers & Evaluation Logic

Conditions evaluate against normalized fields in the Common Evidence Schema (CES):
- `event_type`
- `user_id`, `user_domain`
- `device_id`, `device_name`
- `process_name`, `process_path`, `process_command_line`, `parent_process_name`
- `source_ip`, `destination_ip`, `destination_port`
- `file_path`, `file_hash_sha256`
- `status`

### Supported Matching Operators

#### 1. Exact Match
Matches string or numeric values directly.
```yaml
conditions:
  event_type: "PROCESS_START"
  process_name: "powershell.exe"
```

#### 2. Substring List Match (`_contains`)
Matches if any of the target substrings appear within the field (case-insensitive evaluation).
```yaml
conditions:
  process_command_line_contains:
    - "-EncodedCommand"
    - "-enc"
    - "-ExecutionPolicy Bypass"
    - "-nop"
```

#### 3. List Membership (`_in`)
Matches if the field's value matches any element in the provided list.
```yaml
conditions:
  destination_port_in:
    - 4444
    - 1337
    - 8888
```

#### 4. Numeric Thresholds (`_greater_than` / `_less_than`)
Evaluates numeric quantities (e.g., bytes transferred, duration).
```yaml
conditions:
  bytes_transferred_greater_than: 104857600   # > 100 MB
```

---

## 4. Example Rule Definitions

### Example 1: Credential Access via Mimikatz
```yaml
  - id: "CRED-001"
    name: "Credential Dumping Utility Detected"
    description: "Detects command-line execution or file access associated with credential dumping tools like Mimikatz or ProcDump."
    severity: "CRITICAL"
    category: "CREDENTIAL_ACCESS"
    conditions:
      process_name_contains:
        - "mimikatz"
        - "procdump"
        - "pwdump"
```

### Example 2: Suspicious Administrative Reconnaissance
```yaml
  - id: "DISC-001"
    name: "Local Account Enumeration"
    description: "Detects enumeration of local accounts or security groups via net.exe or whoami.exe."
    severity: "MEDIUM"
    category: "DISCOVERY"
    conditions:
      process_name_in:
        - "whoami.exe"
        - "net.exe"
        - "net1.exe"
      process_command_line_contains:
        - "/all"
        - "localgroup administrators"
        - "user /domain"
```

---

## 5. Indicator of Compromise (IOC) Feeds

ForensiQ supports file-based IOC matching under `data/rules/iocs/` or within YAML rule definitions.

IOC types supported:
- **IPv4 / IPv6 Addresses**: Evaluated against both `source_ip` and `destination_ip`.
- **SHA-256 Hashes**: Evaluated against `file_hash_sha256`.
- **Domain Names**: Evaluated against network destination hostnames.

---

## 6. Testing & Validating Rules

Whenever adding or modifying rules in `data/rules/default_rules.yaml`:

1. **Verify YAML Syntax**: Ensure valid YAML formatting.
2. **Execute Detection Semantics Tests**:
   ```bash
   pytest backend/tests/test_detection_semantics.py -v
   ```
3. **Execute Rule Validation Tests**:
   ```bash
   pytest backend/tests/test_detection_rules.py -v
   ```
4. **End-to-End Test**:
   Upload sample dataset `data/samples/insider_threat_triage.csv` via the UI or run:
   ```bash
   pytest backend/tests/test_e2e_investigation.py -v
   ```
