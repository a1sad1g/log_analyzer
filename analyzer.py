import argparse
import json
from colorama import Fore, Style, init

from analyze.parser import parse_logs, extract_messages_by_type
from analyze.stats import analyze_stats, format_stats
from analyze.security import detect_bruteforce_time_based

init(autoreset=True)


def main():

    parser = argparse.ArgumentParser(description="Security Log Analyze")
    
    parser.add_argument("file", help="Path to log file")
    parser.add_argument("--alerts", action="store_true", help="Show security alerts")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--json", help="Save result as JSON file")
    parser.add_argument("--type", help="Filter by log type [ERROR, WARNING, INFO]")
    
    
    
    args = parser.parse_args()
    data = parse_logs(args.file)
   
    
    result = {}
    
    if args.type:
        messages = extract_messages_by_type(args.file, args.type)
        print(f"\n=== {args.type.upper()} Messages ===")
        for log_type, msg in messages:
            if log_type == "ERROR":
                print(Fore.RED + f"[{log_type}] " + Style.RESET_ALL + msg)
            elif log_type == "WARNING":
                print(Fore.YELLOW + f"[{log_type}] " + Style.RESET_ALL + msg)
            else:
                print(Fore.BLUE + f"[{log_type}] " + Style.RESET_ALL + msg)
        
        
    if args.stats:
        stats = analyze_stats(data)
        print(Fore.CYAN + format_stats(stats))
        result["stats"] = stats
    
    if args.alerts:
        alerts = detect_bruteforce_time_based(data)
        for alert in alerts:
            print(Fore.RED + alert)
        result["alerts"] = alerts
    if args.json:
        with open(args.json, "w") as file:
            json.dump(result, file, indent=4, default=str)
            print(Fore.GREEN + f"\n Result saved to {args.json}")
            
if __name__ == '__main__':
    main()
    

