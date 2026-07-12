import sys

TARGET = "Failed password"
IP_dict ={}
Exception = []


def open_log(path):
    with open(path, 'r') as file:
        return file.readlines()
    

def get_ip(target_log):
    try:
        return target_log[target_log.index("from") + 1]
    except ValueError:
        return None

def ip_control(ip_):
    if ip_ not in IP_dict:
        IP_dict[ip_] = 1
    else:
        IP_dict[ip_] += 1
    

def check_logs(path):
    while True:
        try:
            logs = open_log(path)
            break
        except FileNotFoundError:
            print("Bad path")
            
            
    for row in logs:
        if TARGET in row:
            ip = get_ip(row.split())
            if  ip == None:
                Exception.append(row)
                pass
            else:
                ip_control(ip)
    sort(IP_dict)

def sort(IP_dict):
    for key, value in sorted(IP_dict.items(), key=lambda item: item[1], reverse=True):
        if value > 5:
            print(f"IP: {key} | failed attempts: {value}")
            for suspect_log in Exception:
                print(f"Suspected line: ", suspect_log)


        
                     
check_logs(sys.argv[1])


