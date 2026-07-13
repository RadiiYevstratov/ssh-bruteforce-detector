import sys
import argparse
import json

TARGET = "Failed password"


def code_debug():
    path, time = get_args()
    IP_dict, skipped = check_logs(path=path, time=time)
    print(json.dumps(IP_dict, indent=2))

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Enter path of your log file", type=str)
    parser.add_argument("-t", "--time", help="Enter period of time in minutes to check logs", type=int, default=5)
    args = parser.parse_args()
    return args.path, args.time
    check_ip, skipped= check_logs(path = args.path, time = args.time)


def check_logs(path, time):
    IP_dict ={}
    skipped_lines = []
    try:
        logs = open_log(path)
    except FileNotFoundError:
        print(f"File {path} doesn't exist. Please try enter right path")
        sys.exit(1)
    except PermissionError:
        print(f"Error: no permission to read {path}. Try running with sudo.")
        sys.exit(1)
            
    for row in logs:
        if TARGET in row:
            ip = get_ip(row.split())
            start_time = get_time(row.split())
            if  ip is None:
                skipped_lines.append(row)
            else:
                ip_control(ip, start_time, IP_dict)
    
    return (IP_dict, skipped_lines)


def open_log(path):
    with open(path, 'r') as file:
        return file.readlines()
    

def get_ip(target_log):
    try:
        return target_log[target_log.index("from") + 1]
    except (ValueError, IndexError):
        return None

def get_time(target_log):
    try:
        return target_log[0]
    except (ValueError, IndexError):
        return None


def ip_control(ip_, time, IP_dict):
    if ip_ not in IP_dict:
        IP_dict[ip_] = [time]
    else:
        IP_dict[ip_].append(time)
        IP_dict[ip_].sort()


def print_result(IP_dict, skipped_lines):
    for key, value in sorted(IP_dict.items(), key=lambda item: item[1], reverse=True):
        if value > 5:
            print(f"IP: {key} | failed attempts: {value}")
    for suspect_log in skipped_lines:
        print(f"Suspected line:  {suspect_log}")


        
def start_checking(path, time):
    IP_dict, skipped_lines = check_logs(sys.argv[1])
    for i in IP_dict:
        print(i)
    # print_result(IP_dict, skipped_lines)
    

def suspicious_ip(IP_dict, time):
    for key in IP_dict.keys:
        print(key)


code_debug()
# suspicious_ip(IP_dict, time)