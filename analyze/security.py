from collections import defaultdict
from datetime import timedelta


def detect_bruteforce_time_based(data, threshold=3, window_seconds=10):
    ip_events = defaultdict(list)
    
    for entry in data:
        if entry["ip"] and entry["time"]:
            ip_events[entry["ip"]].append(entry["time"])
    
    alerts = []
    
    for ip, times in ip_events.items():
        times.sort()
        for i in range(len(times)):
            count = 1
            
            for j in range(i + 1, len(times)):
                if times[j] - times[i] <= timedelta(seconds=window_seconds):
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append(f"Brute Force detected from {ip} ({count} attempts in {window_seconds}s)")
                break
    return alerts
    
    
