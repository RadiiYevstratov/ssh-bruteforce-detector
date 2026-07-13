import sys
import argparse
import json
from datetime import datetime, timedelta

TARGET = "Failed password"


def code_debug():
    path, time, failed_target = get_args()
    IP_dict, skipped = check_logs(path=path)
    result_dict = suspicious_ip(IP_dict, time)
    sort_result(result_dict=result_dict, failed_target=failed_target)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Enter path of your log file", type=str)
    parser.add_argument("time", help="Enter period of time in minutes to check logs. Default number is 5", type=int, nargs="?", default=5) 
    parser.add_argument("failed_target", help="Enter how many failed attempt need to be to include to result. Default number is 5", type=int, nargs="?", default=5) 
    args = parser.parse_args()
    return args.path, args.time, args.failed_target


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
    

def suspicious_ip(IP_dict, time):
    converted_list = convert_datetime(IP_dict)
    result_dict = {}
    for key in converted_list.keys():
        result_dict[key] = [None, None, None]

    for key, time_list in converted_list.items():
        for starting_time in time_list:
            max_time = datetime.fromisoformat(str(starting_time)) + timedelta(minutes=time)
            finishing_time = max((finish_time for finish_time in time_list if datetime.fromisoformat(str(finish_time)) < max_time))
            failed_attempts = len(time_list[time_list.index(starting_time):time_list.index(finishing_time )])
            result_dict = result_save(result_dict, key, failed_attempts, starting_time, finishing_time)

    return result_dict

def result_save(result_dict, key, failed_attempts, starting_time, finishing_time):

    if result_dict[key][0] == None or result_dict[key][0] < failed_attempts:
        result_dict[key][0] = failed_attempts
        result_dict[key][1] = starting_time
        result_dict[key][2] = finishing_time
    else:
        pass
    return result_dict
            

def sort_result(result_dict, failed_target):
    pop_list = []
    for  key, value_list in result_dict.items():
        print(value_list)
        if value_list[0] < failed_target:
            pop_list.append(key)
    
    for remove_ip in pop_list:
        result_dict.pop(remove_ip)
    
    print(result_dict)

def convert_datetime(IP_dict):     
    for  value_list in IP_dict.values():
        for value in value_list:
            value = datetime.fromisoformat(str(value))

    return IP_dict

code_debug()



