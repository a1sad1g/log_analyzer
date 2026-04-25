import re
import ipaddress
from datetime import datetime

ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

user_patterns = [
    r"user\s[:=]\s*([a-zA-Z0-9_]+)",
    r"login failed for\s+([a-zA-Z0-9_]+)"
    r"username\s*[:=]\s*([a-zA-Z0-9_]+)"
]

def extract_messages_by_type(file_path, log_type):
    result = []
    pattern = re.compile(rf"\b({log_type})\b[:\s\-\]]+(.*)", re.IGNORECASE)
    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            match = re.search(pattern, line)
            if match:
                messages = match.group(2).strip()
                log_type_found = match.group(1).upper()
                result.append((log_type_found, messages))
        return result


def extract_ip(line):
    match = re.search(ip_pattern, line)
    if match:
        ip = match.group()
        try:
            ipaddress.ip_address(ip)
            return ip        
        except ValueError:
            return None
    return None
        
def extract_user(line):
    for pattern in user_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1)
    return None
    
def extract_time(line):
    match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
    if match:
        return datetime.strptime(match.group(), "%Y-%m-%d %H:%M:%S")
    return None

def get_log_type(line):
    if "ERROR" in line:
        return "ERROR"
    elif "WARNING" in line:
        return "WARNING"
    else:
        return "INFO"


def parse_logs(file_path):
    data = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            
            if not any(k in line for k in ["WARNING", "ERROR", "INFO"]):
                continue
            entry = {
                "line": line,
                "ip": extract_ip(line),
                "user": extract_user(line),
                "time": extract_time(line),
                "type": get_log_type(line)
            }
            data.append(entry)
        return data

