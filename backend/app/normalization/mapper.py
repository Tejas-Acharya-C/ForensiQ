"""Unified entity mapping, transformation, and normalization."""

import hashlib
import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Optional, Tuple, Any, Dict, List
from dataclasses import dataclass, field
from dateutil import parser as date_parser

# --- entities.py ---
def sanitize_string(val: Optional[str]) -> Optional[str]:
    if val is None: return None
    cleaned = str(val).strip()
    if not cleaned or cleaned.lower() in ["null", "none", "n/a", "-", "unknown"]: return None
    return cleaned

def normalize_user_id(user_val: Optional[str]) -> Optional[str]:
    user = sanitize_string(user_val)
    if not user: return None
    return user.strip('"\'')

def normalize_device_id(device_val: Optional[str]) -> Optional[str]:
    dev = sanitize_string(device_val)
    if not dev: return None
    return dev.strip('"\'')

def normalize_process_name(proc_val: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    proc = sanitize_string(proc_val)
    if not proc: return None, None
    base_name = os.path.basename(proc.replace("\\", "/"))
    return base_name.lower(), proc

def normalize_ip_address(ip_val: Optional[str]) -> Optional[str]:
    ip_str = sanitize_string(ip_val)
    if not ip_str: return None
    if ":" in ip_str and not ip_str.startswith("["):
        parts = ip_str.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            ip_str = parts[0]
    try:
        parsed = ipaddress.ip_address(ip_str)
        return str(parsed)
    except ValueError:
        raise ValueError(f"Invalid IP address format: '{ip_val}'")

def normalize_port(port_val: Optional[int | str]) -> Optional[int]:
    if port_val is None: return None
    if isinstance(port_val, str):
        cleaned = sanitize_string(port_val)
        if not cleaned: return None
        if not cleaned.isdigit(): raise ValueError(f"Port value must be an integer, got '{port_val}'")
        port_num = int(cleaned)
    else:
        port_num = int(port_val)
    if not (0 <= port_num <= 65535):
        raise ValueError(f"Port number {port_num} is out of valid range (0-65535)")
    return port_num

def normalize_protocol(proto_val: Optional[str]) -> Optional[str]:
    proto = sanitize_string(proto_val)
    if not proto: return None
    return proto.upper()

HASH_ALGORITHMS: Dict[int, str] = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
    96: "SHA-384",
    128: "SHA-512",
}

SUPPORTED_PREFIXES: Dict[str, str] = {
    "sha256:": "SHA-256",
    "sha512:": "SHA-512",
    "sha384:": "SHA-384",
    "sha1:": "SHA-1",
    "md5:": "MD5",
}

UNSUPPORTED_PREFIXES: Dict[str, str] = {
    "blake2b:": "BLAKE2B",
    "blake2s:": "BLAKE2S",
    "blake2:": "BLAKE2",
    "sha3:": "SHA3",
    "sha3_256:": "SHA3-256",
    "sha3_512:": "SHA3-512",
    "crc32:": "CRC32",
    "ripemd160:": "RIPEMD160",
    "bcrypt:": "BCRYPT",
}


def validate_and_parse_file_hash(
    raw_hash: Optional[str],
    require_byte_verification: bool = False,
) -> Tuple[Optional[str], Dict[str, Any]]:
    """Forensically validates a supplied record-level hash digest without truncation.
    
    Strictly separates two fundamental forensic concepts:
    1. Syntax Validity: Whether the supplied string is valid hex and conforms to a recognized
       standard cryptographic algorithm length (MD5, SHA-1, SHA-256, SHA-384, SHA-512).
    2. Byte Verification: Whether the digest was computed and verified against the original
       raw file content on disk. A log-extracted claimed hash is NEVER marked as byte-verified
       solely because its syntax is valid.
    
    Preserves:
    - raw_value: Exact original supplied value (including prefixes and casing).
    - normalized_digest: Lowercase hex digest without prefix (if valid/applicable).
    - Statuses: VALID, INVALID_LENGTH, MALFORMED_HEX, MISSING, UNVERIFIED, UNSUPPORTED_ALGORITHM.
    
    Returns:
        (canonical_digest, hash_metadata)
    """
    if not raw_hash:
        return None, {
            "raw_value": None,
            "normalized_digest": None,
            "status": "MISSING",
            "syntax_status": "MISSING",
            "verification_status": "NOT_APPLICABLE",
            "is_syntax_valid": False,
            "is_byte_verified": False,
            "is_valid": False,
            "claimed_algorithm": None,
            "detected_algorithm": None,
            "warnings": ["File hash is missing in evidence record"],
        }
    
    raw_str = str(raw_hash).strip()
    if not raw_str or raw_str.lower() in ["null", "none", "n/a", "-", "unknown"]:
        return None, {
            "raw_value": None,
            "normalized_digest": None,
            "status": "MISSING",
            "syntax_status": "MISSING",
            "verification_status": "NOT_APPLICABLE",
            "is_syntax_valid": False,
            "is_byte_verified": False,
            "is_valid": False,
            "claimed_algorithm": None,
            "detected_algorithm": None,
            "warnings": ["File hash is missing in evidence record"],
        }

    lower_str = raw_str.lower()
    claimed_algo = None
    digest = lower_str

    # 1. Check supported prefixes
    for prefix, algo_name in SUPPORTED_PREFIXES.items():
        if lower_str.startswith(prefix):
            claimed_algo = algo_name
            digest = lower_str[len(prefix):].strip()
            break

    # 2. Check unsupported prefixes
    if claimed_algo is None:
        for prefix, algo_name in UNSUPPORTED_PREFIXES.items():
            if lower_str.startswith(prefix):
                claimed_algo = algo_name
                metadata = {
                    "raw_value": raw_str,
                    "normalized_digest": raw_str,
                    "status": "UNSUPPORTED_ALGORITHM",
                    "syntax_status": "UNSUPPORTED_ALGORITHM",
                    "verification_status": "UNVERIFIED",
                    "claimed_algorithm": claimed_algo,
                    "detected_algorithm": None,
                    "is_syntax_valid": False,
                    "is_byte_verified": False,
                    "is_valid": False,
                    "error": f"Unsupported or non-standard hash algorithm '{claimed_algo}'",
                }
                return raw_str, metadata

    # 3. Check for arbitrary unhandled prefixes (e.g. unknown_algo:...)
    if claimed_algo is None and ":" in lower_str and not lower_str.startswith("["):
        prefix_candidate = lower_str.split(":", 1)[0]
        if prefix_candidate.isalpha() and len(prefix_candidate) <= 16:
            claimed_algo = prefix_candidate.upper()
            metadata = {
                "raw_value": raw_str,
                "normalized_digest": raw_str,
                "status": "UNSUPPORTED_ALGORITHM",
                "syntax_status": "UNSUPPORTED_ALGORITHM",
                "verification_status": "UNVERIFIED",
                "claimed_algorithm": claimed_algo,
                "detected_algorithm": None,
                "is_syntax_valid": False,
                "is_byte_verified": False,
                "is_valid": False,
                "error": f"Unrecognized hash algorithm prefix '{claimed_algo}'",
            }
            return raw_str, metadata

    is_hex = all(c in "0123456789abcdef" for c in digest) if digest else False
    digest_len = len(digest)

    # 4. Handle claimed standard algorithm (with prefix)
    if claimed_algo:
        expected_len = next((l for l, a in HASH_ALGORITHMS.items() if a == claimed_algo), None)
        if not is_hex:
            metadata = {
                "raw_value": raw_str,
                "normalized_digest": raw_str,
                "claimed_algorithm": claimed_algo,
                "detected_algorithm": None,
                "status": "MALFORMED_HEX",
                "syntax_status": "MALFORMED_HEX",
                "verification_status": "UNVERIFIED",
                "is_syntax_valid": False,
                "is_byte_verified": False,
                "is_valid": False,
                "error": "Digest contains non-hexadecimal characters",
            }
            return raw_str, metadata
        elif digest_len != expected_len:
            metadata = {
                "raw_value": raw_str,
                "normalized_digest": raw_str,
                "claimed_algorithm": claimed_algo,
                "detected_algorithm": None,
                "expected_length": expected_len,
                "actual_length": digest_len,
                "status": "INVALID_LENGTH",
                "syntax_status": "INVALID_LENGTH",
                "verification_status": "UNVERIFIED",
                "is_syntax_valid": False,
                "is_byte_verified": False,
                "is_valid": False,
                "error": f"Claimed {claimed_algo} length must be {expected_len} hex characters, got {digest_len}",
            }
            return raw_str, metadata
        else:
            status = "UNVERIFIED" if require_byte_verification else "VALID"
            metadata = {
                "raw_value": raw_str,
                "normalized_digest": digest,
                "claimed_algorithm": claimed_algo,
                "detected_algorithm": claimed_algo,
                "status": status,
                "syntax_status": "VALID",
                "verification_status": "UNVERIFIED",
                "is_syntax_valid": True,
                "is_byte_verified": False,
                "is_valid": True,
                "warnings": ["Log-extracted hash: syntax is valid but byte content has not been independently verified against source file."],
            }
            return digest, metadata

    # 5. Handle unprefixed strings
    if not is_hex:
        metadata = {
            "raw_value": raw_str,
            "normalized_digest": raw_str,
            "claimed_algorithm": None,
            "detected_algorithm": None,
            "status": "MALFORMED_HEX",
            "syntax_status": "MALFORMED_HEX",
            "verification_status": "UNVERIFIED",
            "is_syntax_valid": False,
            "is_byte_verified": False,
            "is_valid": False,
            "error": "Digest contains non-hexadecimal characters",
        }
        return raw_str, metadata

    if digest_len in HASH_ALGORITHMS:
        inferred_algo = HASH_ALGORITHMS[digest_len]
        status = "UNVERIFIED" if require_byte_verification else "VALID"
        metadata = {
            "raw_value": raw_str,
            "normalized_digest": digest,
            "claimed_algorithm": None,
            "detected_algorithm": inferred_algo,
            "status": status,
            "syntax_status": "VALID",
            "verification_status": "UNVERIFIED",
            "is_syntax_valid": True,
            "is_byte_verified": False,
            "is_valid": True,
            "warnings": ["Log-extracted hash: syntax is valid but byte content has not been independently verified against source file."],
        }
        return digest, metadata

    # Non-standard length (e.g. 65 characters) - MUST NOT falsely report verified SHA-256
    metadata = {
        "raw_value": raw_str,
        "normalized_digest": raw_str,
        "claimed_algorithm": None,
        "detected_algorithm": None,
        "status": "INVALID_LENGTH",
        "syntax_status": "INVALID_LENGTH",
        "verification_status": "UNVERIFIED",
        "actual_length": digest_len,
        "is_syntax_valid": False,
        "is_byte_verified": False,
        "is_valid": False,
        "error": f"Hex digest length of {digest_len} does not match standard forensic digest (MD5=32, SHA-1=40, SHA-256=64, SHA-384=96, SHA-512=128)",
    }
    return raw_str, metadata


def verify_hash_integrity(raw_hash: Optional[str], file_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """Evaluates cryptographic integrity of a hash against optional raw file bytes.
    
    Demonstrates the separation between syntax validation and byte verification:
    - Syntax validation checks structure and algorithm compliance.
    - Byte verification computes cryptographic digest over actual file content and compares.
    """
    digest, meta = validate_and_parse_file_hash(raw_hash)
    if not meta.get("is_syntax_valid"):
        return meta

    if file_bytes is None:
        meta["status"] = "UNVERIFIED"
        meta["verification_status"] = "UNVERIFIED"
        meta["is_byte_verified"] = False
        meta["warnings"] = ["Hash syntax is valid but raw bytes were not provided for cryptographic verification."]
        return meta

    algo = meta.get("detected_algorithm")
    if algo == "SHA-256":
        computed = hashlib.sha256(file_bytes).hexdigest()
    elif algo == "SHA-512":
        computed = hashlib.sha512(file_bytes).hexdigest()
    elif algo == "MD5":
        computed = hashlib.md5(file_bytes).hexdigest()
    elif algo == "SHA-1":
        computed = hashlib.sha1(file_bytes).hexdigest()
    elif algo == "SHA-384":
        computed = hashlib.sha384(file_bytes).hexdigest()
    else:
        meta["status"] = "UNSUPPORTED_ALGORITHM"
        meta["verification_status"] = "UNVERIFIED"
        meta["is_byte_verified"] = False
        return meta

    if computed.lower() == digest.lower():
        meta["status"] = "VERIFIED"
        meta["verification_status"] = "VERIFIED"
        meta["is_byte_verified"] = True
        meta["computed_digest"] = computed.lower()
    else:
        meta["status"] = "INTEGRITY_MISMATCH"
        meta["verification_status"] = "FAILED"
        meta["is_byte_verified"] = False
        meta["computed_digest"] = computed.lower()
        meta["error"] = f"Computed digest '{computed}' does not match claimed hash '{digest}'"

    return meta


def normalize_file_hash(hash_val: Optional[str]) -> Optional[str]:
    """Preserve supplied hash without truncation. Valid digests normalized to lowercase hex."""
    digest, _ = validate_and_parse_file_hash(hash_val)
    return digest

def normalize_status(status_val: Optional[str]) -> Optional[str]:
    st = sanitize_string(status_val)
    if not st: return None
    st_upper = st.upper()
    if st_upper in ["SUCCESS", "OK", "0", "ALLOW", "ALLOWED", "TRUE", "PASS", "SUCCESSFUL"]: return "SUCCESS"
    if st_upper in ["FAILURE", "FAILED", "FAIL", "DENY", "DENIED", "ERROR", "BLOCKED", "FALSE"]: return "FAILURE"
    return "UNKNOWN"

def normalize_action(action_val: Optional[str]) -> Optional[str]:
    act = sanitize_string(action_val)
    if not act: return None
    return act.upper()


# --- timestamps.py ---
WINDOWS_FILETIME_EPOCH = 116444736000000000

def parse_to_utc(val: Any) -> Optional[datetime]:
    if val is None: return None
    if isinstance(val, datetime):
        if val.tzinfo is None: return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, (int, float)): return _parse_numeric_timestamp(val)
    val_str = str(val).strip()
    if not val_str or val_str.lower() in ["null", "none", "n/a", "unknown", "0"]: return None
    if val_str.isdigit():
        return _parse_numeric_timestamp(int(val_str))
    try:
        dt = date_parser.parse(val_str)
        if dt.tzinfo is None: return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception as exc:
        raise ValueError(f"Unable to parse timestamp string '{val_str}': {exc}")

def _parse_numeric_timestamp(num: int | float) -> datetime:
    if num > 100000000000000:
        epoch_seconds = (num - WINDOWS_FILETIME_EPOCH) / 10000000
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    if num > 100000000000:
        return datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
    return datetime.fromtimestamp(float(num), tz=timezone.utc)


# --- event_types.py ---
CANONICAL_EVENT_TYPES = {
    "PROCESS_CREATE", "PROCESS_TERMINATE", "FILE_CREATE", "FILE_WRITE",
    "FILE_READ", "FILE_DELETE", "NETWORK_CONNECT", "NETWORK_LISTEN",
    "AUTH_LOGIN", "AUTH_LOGOUT", "REGISTRY_SET", "REGISTRY_DELETE",
    "DNS_QUERY", "GENERIC_EVENT", "UNKNOWN"
}

EVENT_TYPE_MAPPINGS = {
    "process_create": "PROCESS_CREATE", "processcreate": "PROCESS_CREATE", "process_start": "PROCESS_CREATE",
    "processstart": "PROCESS_CREATE", "process_creation": "PROCESS_CREATE", "sysmon_1": "PROCESS_CREATE",
    "4688": "PROCESS_CREATE", "exec": "PROCESS_CREATE", "execute": "PROCESS_CREATE",
    "file_create": "FILE_CREATE", "file_write": "FILE_WRITE", "file_modify": "FILE_WRITE",
    "file_delete": "FILE_DELETE", "sysmon_11": "FILE_CREATE", "network_connect": "NETWORK_CONNECT",
    "networkconnect": "NETWORK_CONNECT", "connection": "NETWORK_CONNECT", "net_connect": "NETWORK_CONNECT",
    "sysmon_3": "NETWORK_CONNECT", "conn": "NETWORK_CONNECT", "http": "NETWORK_CONNECT", "dns": "DNS_QUERY",
    "auth_login": "AUTH_LOGIN", "logon": "AUTH_LOGIN", "login": "AUTH_LOGIN", "login_success": "AUTH_LOGIN",
    "login_failed": "AUTH_LOGIN", "4624": "AUTH_LOGIN", "4625": "AUTH_LOGIN",
    "auth_logout": "AUTH_LOGOUT", "logout": "AUTH_LOGOUT", "4634": "AUTH_LOGOUT"
}

def normalize_event_type(raw_event_type: Optional[str]) -> str:
    clean_type = sanitize_string(raw_event_type)
    if not clean_type: return "UNKNOWN"
    upper_type = clean_type.upper()
    if upper_type in CANONICAL_EVENT_TYPES: return upper_type
    lookup_key = clean_type.lower().replace(" ", "_").replace("-", "_")
    if lookup_key in EVENT_TYPE_MAPPINGS: return EVENT_TYPE_MAPPINGS[lookup_key]
    return "UNKNOWN"


# --- field_mapper.py ---
@dataclass
class SourceFieldMapping:
    source_type: str
    timestamp_fields: List[str] = field(default_factory=lambda: ["timestamp", "time", "event_time", "created_at", "TimeCreated", "utc_time"])
    event_type_fields: List[str] = field(default_factory=lambda: ["event_type", "event", "EventID", "action_type", "type", "activity"])
    user_fields: List[str] = field(default_factory=lambda: ["user_id", "user", "username", "user_name", "UserName", "account", "TargetUserName", "src_user"])
    device_fields: List[str] = field(default_factory=lambda: ["device_id", "host", "hostname", "computer", "Computer", "device", "host_name", "machine"])
    session_fields: List[str] = field(default_factory=lambda: ["session_id", "session", "logon_id", "TargetLogonId"])
    process_id_fields: List[str] = field(default_factory=lambda: ["process_id", "pid", "ProcessId", "NewProcessId"])
    process_name_fields: List[str] = field(default_factory=lambda: ["process_name", "process", "Image", "NewProcessName", "app", "exe"])
    parent_process_fields: List[str] = field(default_factory=lambda: ["parent_process_name", "parent_process", "ParentImage", "ParentProcessName"])
    file_path_fields: List[str] = field(default_factory=lambda: ["file_path", "path", "TargetFilename", "filename", "TargetFilePath"])
    file_hash_fields: List[str] = field(default_factory=lambda: ["file_hash", "hash", "sha256", "md5", "Hashes"])
    ip_fields: List[str] = field(default_factory=lambda: ["ip_address", "ip", "DestinationIp", "DestIP", "dest_ip", "src_ip", "client_ip", "remote_ip", "host_ip"])
    port_fields: List[str] = field(default_factory=lambda: ["port", "DestinationPort", "DestPort", "dest_port", "src_port", "remote_port"])
    protocol_fields: List[str] = field(default_factory=lambda: ["protocol", "proto", "Protocol"])
    action_fields: List[str] = field(default_factory=lambda: ["action", "Action", "command", "operation", "method"])
    status_fields: List[str] = field(default_factory=lambda: ["status", "Status", "result", "outcome"])

DEFAULT_MAPPINGS: Dict[str, SourceFieldMapping] = {
    "CSV_GENERIC": SourceFieldMapping(source_type="CSV_GENERIC"),
    "JSON_GENERIC": SourceFieldMapping(source_type="JSON_GENERIC"),
    "WINDOWS_EVTX": SourceFieldMapping(
        source_type="WINDOWS_EVTX",
        timestamp_fields=["TimeCreated", "SystemTime", "timestamp"],
        event_type_fields=["EventID", "Task", "event_type"],
        user_fields=["TargetUserName", "SubjectUserName", "UserName", "user"],
        device_fields=["Computer", "ComputerName", "hostname"],
        process_name_fields=["NewProcessName", "Image", "process_name"],
        parent_process_fields=["ParentProcessName", "ParentImage"],
        process_id_fields=["ProcessId", "NewProcessId"],
        file_path_fields=["TargetFilename", "FilePath"],
        ip_fields=["DestinationIp", "IpAddress", "SourceIp"],
        port_fields=["DestinationPort", "SourcePort"],
    ),
    "SYSLOG": SourceFieldMapping(
        source_type="SYSLOG",
        timestamp_fields=["timestamp", "time", "date"],
        event_type_fields=["facility", "program", "appname"],
        device_fields=["host", "hostname"],
        process_name_fields=["program", "process"],
        user_fields=["user", "username"],
    ),
    "ZEEK_CONN": SourceFieldMapping(
        source_type="ZEEK_CONN",
        timestamp_fields=["ts", "timestamp"],
        ip_fields=["id.resp_h", "id.orig_h", "dest_ip"],
        port_fields=["id.resp_p", "id.orig_p", "dest_port"],
        protocol_fields=["proto", "service"],
        action_fields=["conn_state"],
    ),
}

def get_source_mapping(source_type: str) -> SourceFieldMapping:
    return DEFAULT_MAPPINGS.get(source_type.upper(), DEFAULT_MAPPINGS["CSV_GENERIC"])

def extract_field_value(raw_data: Dict[str, Any], candidate_names: List[str]) -> Optional[Any]:
    for name in candidate_names:
        if name in raw_data and raw_data[name] is not None:
            return raw_data[name]
    lower_map = {k.lower(): k for k in raw_data.keys()}
    for name in candidate_names:
        lower_name = name.lower()
        if lower_name in lower_map:
            actual_key = lower_map[lower_name]
            if raw_data[actual_key] is not None:
                return raw_data[actual_key]
    return None
