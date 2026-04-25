from collections import Counter

def analyze_stats(data):
    types = [d["type"] for d in data]
    users = [d["user"] for d in data if d["user"]]
    ips = [d["ip"] for d in data if d["ip"]]
    
    return {
        "log_types": Counter(types),
        "top_users": Counter(users).most_common(3),
        "top_ips": Counter(ips).most_common(3)
    }

def format_stats(stats):
    lines = []
    
    lines.append("=== Statistics ===\n")
    
    for log_type, count in stats["log_types"].most_common():
        lines.append(f" {log_type:<8}: {count}")
        
    lines.append("\n Top users:")
    if stats["top_users"]:
        for user, count in stats["top_users"]:
            lines.append(f" {user:<10}: {count} attempts")
    else:
        lines.append("\n  No user data found")
    
    lines.append("\n Top IPs:")
    if stats["top_ips"]:
        for ip, count in stats["top_ips"]:
            lines.append(f" {ip:<15}: {count} attempts")
    else:
        lines.append("\n  No IP data found")
    return "\n".join(lines)
    
        
