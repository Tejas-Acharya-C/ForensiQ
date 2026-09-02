# ForensiQ Rules & Detection Authoring Guide

ForensiQ includes a flexible deterministic rule engine. Rules are defined in YAML under `data/rules/default_rules.yaml`.

---

## 1. Rule File Structure

Rules are specified as a YAML list of rule objects:

```yaml
rules:
  - id: "PROC-001"
    name: "Suspicious PowerShell Execution"
    description: "Detects execution of PowerShell with encoded command or bypass flags"
    severity: "HIGH"
    category: "PROCESS_EXECUTION"
    conditions:
      process_name: "powershell.exe"
      command_line_contains:
        - "-EncodedCommand"
        - "-enc"
        - "-ExecutionPolicy Bypass"
        - "-nop"

  - id: "PROC-002"
    name: "Credential Dumping Tool Detected"
    description: "Detects execution of known credential dumping utilities"
    severity: "CRITICAL"
    category: "CREDENTIAL_ACCESS"
    conditions:
      process_name_contains:
        - "mimikatz"
        - "procdump"
        - "pwdump"
```

---

## 2. Rule Fields Reference

| Field | Required | Type | Description |
| :--- | :--- | :--- | :--- |
| `id` | Yes | String | Unique rule identifier (e.g. `PROC-001`, `AUTH-SEQ-001`). |
| `name` | Yes | String | Human-readable title of the rule. |
| `description` | Yes | String | Summary of the threat scenario. |
| `severity` | Yes | String | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `category` | Yes | String | ATT&CK tactic category (e.g., `PROCESS_EXECUTION`, `CREDENTIAL_ACCESS`, `COMMAND_AND_CONTROL`). |
| `conditions` | Yes | Object | Pattern matching criteria evaluated against normalized evidence fields. |

---

## 3. Supported Condition Matchers

1. **Exact String Match**: `process_name: "powershell.exe"`
2. **Substring List Match**: `command_line_contains: ["-enc", "-nop"]`
3. **Case Insensitivity**: All process name and command line matchers operate case-insensitively.
4. **IOC IP Matching**: IP indicator matching automatically checks destination and source IP fields against threat feeds.

---

## 4. Testing Custom Rules

After adding new rules to `data/rules/default_rules.yaml`, verify rule execution by running the detection test suite:

```bash
pytest backend/tests/test_detection_semantics.py -v
```
