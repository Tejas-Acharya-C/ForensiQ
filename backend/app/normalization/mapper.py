"""Unified entity mapping, transformation, and normalization."""

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

def normalize_file_hash(hash_val: Optional[str]) -> Optional[str]:
    h = sanitize_string(hash_val)
    if not h: return None
    clean_hex = h.lower().strip()
    if len(clean_hex) in [32, 40, 64]:
        if all(c in "0123456789abcdef" for c in clean_hex):
            return clean_hex
    return clean_hex

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
