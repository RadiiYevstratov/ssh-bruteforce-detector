import sys

TARGET = "Failed password"



def open_log(path):
    with open(path, 'r') as file:
        return file.readlines()
    

def get_ip(target_log):
    try:
        return target_log[target_log.index("from") + 1]
    except (ValueError, IndexError):
        return None


    

def check_logs(path):
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
            if  ip is None:
                skipped_lines.append(row)
            else:
                ip_control(ip, IP_dict)
    
    return (IP_dict, skipped_lines)

def ip_control(ip_, IP_dict):
    if ip_ not in IP_dict:
        IP_dict[ip_] = 1
    else:
        IP_dict[ip_] += 1

def print_result(IP_dict, skipped_lines):
    for key, value in sorted(IP_dict.items(), key=lambda item: item[1], reverse=True):
        if value > 5:
            print(f"IP: {key} | failed attempts: {value}")
    for suspect_log in skipped_lines:
        print(f"Suspected line:  {suspect_log}")


        
def start_checking():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <path_to_log>")
        sys.exit(1)
    else:
        IP_dict, skipped_lines = check_logs(sys.argv[1])
        print_result(IP_dict, skipped_lines)

start_checking()

