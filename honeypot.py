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

with open("config.json") as f:
    config = json.load(f)

logs = config["logs"]
log_directory = os.path.dirname(logs)
if log_directory and not os.path.exists(log_directory):
    os.makedirs(log_directory)
    print(f"Created directory: {log_directory}")
cleanup_interval = config["cleanup_interval"]
host = config['bind_host']
pureiplogs = config["pureiplogs"]
enable_webhook = config["enable_webhook"]
webhook_url = config["webhook_url"]
max_pings = config["max_pings"]
time_window = config["time_window"]
kick_message = config["kick_message"]
port = config["port"]

if max_pings < 1:
    print("max_pings must be at least 1.")
    exit(1)
if time_window < 1:
    print("time_window must be at least 1.")
    exit(1)
if port < 1 or port > 65535:
    print("Invalid port number. Please use a port between 1 and 65535.")
    exit(1)
if enable_webhook and webhook_url in ("your-webhook-here", ""):
    print("Webhook enabled but no URL provided. Disabling webhook.")
    enable_webhook = False
if cleanup_interval < 1:
    print("cleanup_interval must be at least 1 second.")
    exit(1)

ip_requests = {}
ip_requests_lock = Lock()
log_lock = Lock()



def send_webhook(webhook_url, message):
    if enable_webhook == False:
        return
    data = {"content": message}
    headers = {"Content-Type": "application/json"}
    try:
        requests.post(webhook_url, json=data, headers=headers, timeout=5)
    except Exception as e:
        print(f"Webhook error: {e}")

def lookup_ip(ip_address=None):
    url = f"http://ip-api.com/json/{ip_address}" if ip_address else "http://ip-api.com/json/"
    try:
        api = requests.get(url, headers={'User-Agent': 'MCHoneypot/1.0'}, timeout=5)
        return api.json()
    except Exception as e:
        print(f"IP lookup failed for {ip_address} with error: {e}")
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
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    location_isp = lookup_ip(ip_address)
    country = location_isp.get("country") or "Unknown"
    isp = location_isp.get("isp") or "Unknown"
    connection = (
        f'[{timestamp}] Ping from: `{ip_address}:{port_num}`\n'
        f'Country: {country}\n'
        f'ISP: {isp}'
    )
    print(connection)
    with log_lock:
        with open(logs, "a") as f:
            f.write(f"[{timestamp}] Ping from: `{ip_address}:{port_num}`\nCountry: {country}\nISP: {isp}\n")
        with open(pureiplogs, "a") as f:
            f.write(f"{ip_address}\n")
    send_webhook(webhook_url, connection)

def run_honeypot(host=host, port=port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        
        send_webhook(webhook_url, f' **Honeypot started on port {port}**')
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
                    print(f"Login attempt from: {username} at {ip_address}")
                    send_webhook(webhook_url, f"**Login attempt from: `{username}` `{ip_address}`**")
                    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    with log_lock:
                        with open(logs, "a") as f:
                            f.write(f"[{timestamp}] Login attempt from: {username} {ip_address}\n")
                        with open(pureiplogs, "a") as f:
                            f.write(f"{ip_address} (login attempt)\n")
                    reason = json.dumps(kick_message)
                    reason_encoded = reason.encode("utf-8")
                    time.sleep(random.randint(1,4))
                    packet = send_varint(0x00) + send_varint(len(reason_encoded)) + reason_encoded
                    client_socket.sendall(send_varint(len(packet)) + packet)

                else:
                    client_socket.close()

            except Exception as e:
                print(f"packet error: {e}")
            finally:
                client_socket.close()

    except Exception as e:
        print(f"server error: {e}")
    finally:
        server_socket.close()

timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
with log_lock:
    with open(logs, "a") as f:
        f.write(f"\n--------------------------------------------------------\n[{timestamp}] Honeypot started on port {port}.\n--------------------------------------------------------\n")
Thread(target=cleanup_ip_requests, daemon=True).start()

print(f"""
Best Minecraft honeypot started!
  Port:             {port}
  Host:             {host}
  Max pings:        {max_pings}
  Time window:      {time_window}s
  Cleanup interval: {cleanup_interval}s
  Webhook:          {"enabled" if enable_webhook else "disabled"}
  Logs:             {logs}
  IP logs:          {pureiplogs}
""")

run_honeypot()