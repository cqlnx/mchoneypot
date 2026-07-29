import socket
import os
import datetime
import requests
import time
import json
import struct
import copy
import random
from io import BytesIO
from threading import Thread, Lock
from colorama import init


YELLOW = '\033[1;33m'
RESET = '\033[0m'
GREEN = '\033[1;32m'
RED = '\033[1;31m'

init()


get_current_time = lambda : datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def print_error(text : str):

    print(RED + text + RESET + '\n')
    
with open("config.json") as f:
    config = json.load(f)

enable_reports = config["enable_reports"]
abuseip_api_key = config["abuseip_api_key"]
abuseip_reason_message = config["abuseip_reason_message"]
cleanup_interval = config["cleanup_interval"]
host = config['bind_host']
pureiplogs = config["pureiplogs"]
enable_webhook = config["enable_webhook"]
webhook_url = config["webhook_url"]
max_pings = config["max_pings"]
time_window = config["time_window"]
kick_message = config["kick_message"]
port = config["port"]
CACHE_TTL = config["cache_ttl"]
REPORT_TTL = config["report_ttl"]  
logs = config["logs"]
logsdir = config["logs_directory"]

log_dir = os.path.join(logsdir,logs) # by using os.path.join, we avoid potential errors in file paths.
log_ip_dir = os.path.join(logsdir,pureiplogs)


if logsdir and not os.path.exists(logsdir):
    os.makedirs(logsdir)
    print(f"Created directory: {logsdir}")
if max_pings < 1:

    print_error("max_pings must be at least 1.")

    exit(1)
if time_window < 1:
    print_error("time_window must be at least 1.")
    exit(1)
if port < 1 or port > 65535:

    print_error("Invalid port number. Please use a port between 1 and 65535.")

    exit(1)
if enable_webhook and webhook_url in ("your-webhook-here", ""):

    print_error("Webhook enabled but no URL provided. Disabling webhook.")
    exit(1)
if cleanup_interval < 1:

    print_error("cleanup_interval must be at least 1 second.")

    exit(1)

if CACHE_TTL < 1:

    print_error("cache_ttl must be at least 1 second.")
    exit(1)

if enable_reports and abuseip_api_key in ("your-abuseip-api-key-here", ""):

    print_error("Reports enabled but no AbuseIPDB API key provided.")
    exit(1)

ip_requests = {}
ip_requests_lock = Lock()
log_lock = Lock()
ip_cache = {}
ip_cache_lock = Lock()
report_cache = {}
report_cache_lock = Lock()

def ips_ignore():

    try:
        with open('ignore-list.txt','r') as list:

            return [ip.replace('\n','') for ip in list.readlines()]

    except FileNotFoundError:

        return []

ignore_list = ips_ignore()

def save_file(dir : str, content : str):


    with log_lock:

        with open(dir, "a") as f:
        
            f.write(content)


def report_ip(ip_address):
    global enable_reports
    if not enable_reports:
        return
    with report_cache_lock:
        now = time.time()
        if ip_address in report_cache:
            last_reported = report_cache[ip_address]
            if now - last_reported < REPORT_TTL:
                return 
        report_cache[ip_address] = now
    url = "https://api.abuseipdb.com/api/v2/report"
    headers = {
        "Key": abuseip_api_key,
        "Accept": "application/json"
    }
    data = {
        "ip": ip_address,
        "categories": "14",
        "comment": abuseip_reason_message
    }
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            print(f"[AbuseIPDB] Successfully reported {ip_address}")

        elif response.status_code == 429:
            print_error(f"[AbuseIPDB] Rate limit hit! (Your API quota is likely exhausted)")
            enable_reports = False

        else:
            print_error(f"[AbuseIPDB] Error {response.status_code}: {response.text}")

    except requests.exceptions.RequestException as e:

        print_error(f"[AbuseIPDB] Connection error for {ip_address}: {e}")


def send_webhook(webhook_url, message):
    if enable_webhook == False:
        return
    data = {"content": message}
    headers = {"Content-Type": "application/json"}
    try:

        requests.post(webhook_url, json=data, headers=headers, timeout=5)
    except Exception as e:

        print_error(f"Webhook error: {e}")

def lookup_ip(ip_address=None):
    now = time.time()
    with ip_cache_lock:

        if ip_address in ip_cache:

            data, timestamp = ip_cache[ip_address]

            if now - timestamp < CACHE_TTL:
                return data
            
    url = f"http://ip-api.com/json/{ip_address}" if ip_address else "http://ip-api.com/json/"
    try:
        api = requests.get(url, headers={'User-Agent': 'MCHoneypot/1.0'}, timeout=5)
        data = api.json()
        with ip_cache_lock:
            ip_cache[ip_address] = (data, now)
        return data

    except Exception as e:
        print_error(f"IP lookup failed for {ip_address} with error: {e}")
        return {}

def read_varint(sock):
    num = 0
    for i in range(5):
        byte = sock.recv(1)
        if not byte:
            return 0
        byte = byte[0]
        num |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            break
    return num

def max_len(list : list[str]):

    if not list:

        return 0

    last = len(list[0])

    for el in list:

        current = len(el)

        if current > last:

            last = current

    return last

def create_table(**kwargs):

    keys = []
    items = kwargs.items()
    text = ''

    for key,_ in items:

        keys.append(key)

    max_size = max_len(keys)


    for key,value in items:

        text += f'{YELLOW}{key.capitalize().replace('_',' ')}:{RESET}{' ' * (max_size + 1 - len(key))}{value}\n'

    return text

def save_info_players(username : str,ip : str):

    timestamp = get_current_time()

    
    save_file(log_dir,f"[{timestamp}] Login attempt from: {username} {ip}\n\n")

    save_file(log_ip_dir,f"{ip} (login attempt)\n")


def save_info_hits(ip : str, port,country : str,isp : str):

    timestamp = get_current_time()

    save_file(log_dir,f"[{timestamp}] Ping from: `{ip}:{port}`\nCountry: {country}\nISP: {isp}\n\n")

    save_file(log_ip_dir,ip+'\n')


def read_varint_from_buffer(buf):
    num = 0
    for i in range(5):
        byte = buf.read(1)
        if not byte:
            return 0
        byte = byte[0]
        num |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            break
    return num

def send_varint(value):
    out = b""
    while True:
        temp = value & 0x7F
        value >>= 7
        if value:
            out += struct.pack("B", temp | 0x80)
        else:
            out += struct.pack("B", temp)
            break
    return out

def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connection closed early")
        data += chunk
    return data

def cleanup_ip_requests():
    while True:
        time.sleep(cleanup_interval)
        now = time.time()
        with ip_requests_lock:
            expired = [ip for ip, times in ip_requests.items() 
                      if not any(now - t < time_window for t in times)]
            
            for ip in expired:
                del ip_requests[ip]

        with ip_cache_lock:

            expired_ips = [ip for ip, (_, ts) in ip_cache.items() if now - ts >= CACHE_TTL]
            for ip in expired_ips:
                del ip_cache[ip]

        with report_cache_lock:

            expired_reports = [ip for ip, ts in report_cache.items() if now - ts >= REPORT_TTL]
            for ip in expired_reports:
                del report_cache[ip]

def send_mc_status(client_socket):
    response = copy.deepcopy(config["response"])

    base_online = response["players"]["online"]
    jitter = random.randint(-1, 1)
    new_online = max(0, base_online + jitter)

    response["players"]["online"] = new_online

    full_sample = response["players"].get("sample", [])
    random.shuffle(full_sample)

    response["players"]["sample"] = full_sample[:new_online]

    json_data = json.dumps(response).encode("utf-8")

    packet = b""
    packet += send_varint(0x00)
    packet += send_varint(len(json_data))
    packet += json_data

    client_socket.sendall(send_varint(len(packet)) + packet)

def log_hit(ip_address, port_num):

    timestamp = get_current_time()

    if ip_address in ips_ignore():

        return

    location_isp = lookup_ip(ip_address)
    country = location_isp.get("country") or "Unknown"
    isp = location_isp.get("isp") or "Unknown"
    connection = (
        f'{GREEN}- PING:{RESET} from: `{ip_address}:{port_num}` [{timestamp}]\n'
        f'Country: {country}\n'
        f'ISP: {isp}\n'
    )
    print(connection)

    save_info_hits(ip=ip_address, 
              port=port_num,
              country=country,
              isp=isp,
    )


    send_webhook(webhook_url, connection)
    report_ip(ip_address)

def run_honeypot(host=host, port=port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        
        send_webhook(webhook_url, f' **Honeypot started on port {port}**')

        print('Best Minecraft honeypot started!\n')

        table = create_table(repoting="enabled" if enable_reports else "disabled",
                     port=port,
                     host=host,
                     max_Pings=max_pings,
                     time_window=f'{time_window}s',
                     cleanup_interval=f'{cleanup_interval}s',
                     cache_TTL=f'{CACHE_TTL}s',
                     report_TTL=f'{REPORT_TTL}',
                     webhook="enabled" if enable_webhook else "disabled",
                     logs=log_dir,
                     IP_logs=log_ip_dir,
                     ignore_list=ignore_list)

        print(table)

        print("waiting for scanners ;)\n")

        while True:
            client_socket, client_address = server_socket.accept()
            client_socket.settimeout(10.0)
            ip_address = client_address[0]
            port_num = client_address[1]
            now = time.time()

            with ip_requests_lock:
                if ip_address not in ip_requests:
                    ip_requests[ip_address] = []
                ip_requests[ip_address] = [t for t in ip_requests[ip_address] if now - t < time_window]
                if len(ip_requests[ip_address]) >= max_pings:
                    print(f"{ip_address} exceeded rate limit, closing connection")
                    client_socket.close()
                    continue
                ip_requests[ip_address].append(now)

            Thread(target=log_hit, args=(ip_address, port_num)).start()

            try:
                packet_length = read_varint(client_socket)
                packet_data = recv_exact(client_socket, packet_length)
                buffer = BytesIO(packet_data)

                packet_id = read_varint_from_buffer(buffer)
                if packet_id != 0x00:
                    client_socket.close()
                    continue

                _protocol = read_varint_from_buffer(buffer)
                addr_len = read_varint_from_buffer(buffer)
                buffer.read(addr_len)
                buffer.read(2) 
                next_state = read_varint_from_buffer(buffer)

                if next_state == 1: 
                    packet_length = read_varint(client_socket)
                    packet_data = recv_exact(client_socket, packet_length)
                    buffer = BytesIO(packet_data)
                    read_varint_from_buffer(buffer)

                    send_mc_status(client_socket)
                    time.sleep(0.05)

                    packet_length = read_varint(client_socket)
                    packet_data = recv_exact(client_socket, packet_length)
                    buffer = BytesIO(packet_data)
                    ping_id = read_varint_from_buffer(buffer)
                    if ping_id == 0x01:
                        payload = buffer.read(8)
                        pong = send_varint(0x01) + payload
                        client_socket.sendall(send_varint(len(pong)) + pong)

                elif next_state == 2: 
                    packet_length = read_varint(client_socket)
                    packet_data = recv_exact(client_socket, packet_length)
                    buffer = BytesIO(packet_data)
                    read_varint_from_buffer(buffer) 
                    name_len = read_varint_from_buffer(buffer)
                    username = buffer.read(name_len).decode("utf-8")

                    print(f"{YELLOW}- LOGIN :{RESET} {username} at {ip_address}\n")

                    send_webhook(webhook_url, f"**Login attempt from: `{username}` `{ip_address}`**")
                    

                    save_info_players(username=username,
                                      ip=ip_address)

                    reason = json.dumps(kick_message)

                    reason_encoded = reason.encode("utf-8")
                    time.sleep(random.randint(1,4))
                    packet = send_varint(0x00) + send_varint(len(reason_encoded)) + reason_encoded
                    client_socket.sendall(send_varint(len(packet)) + packet)

                else:
                    client_socket.close()

            except Exception as e:

                print_error(f"packet error: {e}")

            finally:
                client_socket.close()

    except Exception as e:

        print_error(f"server error: {e}")

    finally:

        server_socket.close()

timestamp = get_current_time()


save_file(log_dir,f"\n{'-'*50}\n[{timestamp}] Honeypot started on port {port}.\n{'-'*50}\n")

Thread(target=cleanup_ip_requests, daemon=True).start()

run_honeypot()
