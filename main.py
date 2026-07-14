import sys
import argparse
import json
from datetime import datetime, timedelta

TARGET = "Failed password"


def main():
    path, time, failed_target = get_args()
    IP_dict, skipped = check_logs(path=path)
    result_dict = suspicious_ip(IP_dict, time)
    final_dict = sort_result(result_dict=result_dict, failed_target=failed_target)
    print_outcome(final_dict=final_dict, skipped= skipped, time=time, failed_target=failed_target)

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
            if  ip is None or start_time is None:
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
        time = datetime.fromisoformat(target_log[0])
        return time
    except (ValueError, IndexError):
        return None


def ip_control(ip_, time, IP_dict):
    if ip_ not in IP_dict:
        IP_dict[ip_] = [time]
    else:
        IP_dict[ip_].append(time)
    IP_dict[ip_].sort()

    

def suspicious_ip(IP_dict, time):
    converted_list = IP_dict
    result_dict = {}
    for key in converted_list.keys():
        result_dict[key] = [None, None, None]

    for key, time_list in converted_list.items():
        for starting_time in time_list:
            max_time = starting_time + timedelta(minutes=time)
            finishing_time = max((finish_time for finish_time in time_list if finish_time < max_time))
            failed_attempts = len(time_list[time_list.index(starting_time):time_list.index(finishing_time )]) + 1
            result_dict = result_save(result_dict, key, failed_attempts, starting_time, finishing_time)

    return result_dict

def result_save(result_dict, key, failed_attempts, starting_time, finishing_time):

    if result_dict[key][0] is None or result_dict[key][0] < failed_attempts:
        result_dict[key][0] = failed_attempts
        result_dict[key][1] = starting_time
        result_dict[key][2] = finishing_time

    return result_dict
            

def sort_result(result_dict, failed_target):
    pop_list = []
    for  key, value_list in result_dict.items():
        if value_list[0] <= failed_target:
            pop_list.append(key)
    
    for remove_ip in pop_list:
        result_dict.pop(remove_ip)

    result_dict = dict(sorted(result_dict.items(), key=lambda item: item[1][0], reverse=True))
    
    return result_dict


def print_outcome(final_dict, skipped, time, failed_target):
    print(f"Test has been done. Settings: Period to check is {time} minutes; Failed target to detect is {failed_target}")
    for key, values in final_dict.items():
        print(f"IP: {key} | Failed attemps: {values[0]} | Analyzed since: {values[1].strftime("%d.%m.%Y %H:%M:%S")} to {values[2].strftime("%d.%m.%Y %H:%M:%S")}")
    
    for log in skipped:
        print(log)

main()



