import socket
import datetime
import requests
import time
import json
import struct
from io import BytesIO
from threading import Thread

# saves logs into these files
logs = 'honeypothits.txt'
pureiplogs = 'honeypotips.txt'

# ADD YOUR WEBHOOK URL HERE
webhook_url = 'your-webhook-here'

max_pings = 5 # ratelimit
time_window = 300 # ratelimit
ip_requests = {}

def send_discord_message(webhook_url, message):
    data = {"content": message}
    headers = {"Content-Type": "application/json"}
    try:
        requests.post(webhook_url, json=data, headers=headers, timeout=5)
    except Exception as e:
        print(f"Discord webhook error: {e}")

def lookup_ip(ip_address=None):
    url = f"http://ip-api.com/json/{ip_address}" if ip_address else "http://ip-api.com/json/"
    try:
        api = requests.get(url, timeout=5)
        return api.json()
    except:
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

# you can customize this response to whatever you want
# right now has a picture of a pot of honey and some fakeplayers
def send_mc_status(client_socket):
    response = {
      "version": {"name": "1.21.11", "protocol": 774},
      "players": {"max": 20,"online": 4,"sample": [{"name": "Notch", "id": "069a79f4-44e9-4726-a5be-fca90e38aaf5"},{"name": "Herobrine", "id": "f84c6a79-0a4e-45e0-879b-cd49ebd4c4e2"},{"name": "Dinnerbone", "id": "61699b2e-d327-4a01-9f1e-0ea8c3f06bc6"},{"name": "popiiumaa", "id": "6f22dc59-9977-43ba-8699-dcf481600a1c"}]},
      "description": {"text": "we love honey ;)"},
      "favicon": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAAeFBMVEUAAAD/1FnwvUTzv0XyvkT/1loJBgDot0JLMQLru0XDlzO7jitaSBv70FbNpj+whShUOAbZqTpePQMkFwCkeiFwWSFAKQIwHwF4Ugrisj+YbhmUeTCJYRMUDQBqRwb3y1JkUiCIbivJnjfxxE56YiStjzqhgzTYskku4MG+AAAEGUlEQVRYw81Xi46rOAy9kEAIhACFAOFRHgX6/3+4Tlo6pYSdcqWV1tK0oZocjp1jx/7z539lbpsWee4dWw5WpK17sL24VlHg+8GH+SNfLeF8DLImTo0QeZPYaG83y9ma1fEmNyCkZYLsnWEUWjtzaFPsAbzIsN+2O8tgju/tI3BNsGG/iQAA8Nj9FsAyAozxnsHFR98zCHJDDCr6dQy6pjWcwjXQp4jBfqPgxwaA1iuVjkaeSEkIfdG5GRBIdE0/94MMswosUxZFwQOKKA57CMeSH0pw89Kn2FbkKRhZTfHAnUlLdpN+yNgoo8MwWs796v4m42cMLLOF1Y8T7SXAR/txeAAAYnpRKBpinyUAGVWuZ+nGwZsDePN1EIGtD22p0wAj9Uml3k4J1b9pD8JQ1QQr7PTyZZG38QAnC+DgoPcRJtEkphHQ5ppCAam5RflcT9MczrWixOdQ5fTlGYQ80y+tY1URBuYjWrMhE7AgIp4dh/d3KvqpXmYeDj1UKNIPCoBf200pGRjHNhETRQGLKJKTkABQW848dXc2d7q0zT1QWgR8KCWk7zGkUy8xBnCbTBPBNvKZDwBT5yyDdWejo0NP+hH+Zkevy/S9EtAJ3o1lX6OEKUo4YYvsRX936trhjDsqfE5YD+ECvz3OsXgCjAqACBEsw8SEhFcrAMlqwBCzpQGWeahvine/6Ai8AbQaABjHjImJ9dxn44NBxpk/DN2gAMRQL8pza2Yvd14u6P/nvfATIsWAHgzgKxjZ6Pd3DcBV3NW2mxC3NZ3SJ4NXDCCIYoBX1wiUOLAEuBBRKwBwG6SkY8+WtTQ/j3Etp4MgCkYQClogMmIZHtmMgPLs0N7v7vMCZ2ktTIdQC6ndpMLSK0XXcIRy6IVgNSxEhuky3ByIvOjFsNwAaniq2YnWdHwICUtfKZpIlQljFI0qGSQ8ISXejs9cl7bb8iRgWdmaCw8pQzL9pKEqz/oBr2VVheBRDn9q+3o5FOYb4a20d+Z6sKZz2kj8C4Khtv/k0p/WfC1+QOxqc7Bm8yqELzC6LtQGixuufq54L8P2l4axuvzUSjb5261A7LOGeZm+Xwv4LACKLu1bbxCgswC0eu9y8t+UsPcgKYtth3bSBxRc2k1/c9aHrQd/cQ5bD1R/M56igKPLtslx4+zUftJ8tmlFKU+EEY27Hqk9FUaaee6+Vyf4L0WwhtFHJ0Swb/ddr/r6JPchfDSK31JA/rU1TTzxtxRolRtnpm8pQAhT89AVN19pAUfewdhWXDP7VwSM5AEBRaGEy2mtecZyaJPEr2L3aPBMr2WTBWMiqa2mhtfkpycIShI1M5bXOD0eXdvCiy+A0lS6538ZPFUV7L3EedG6/zb7Psdfz4uVXZ4GSzX2Hg+9JqgP++8G9n8AxnReR+9zFycAAAAASUVORK5CYII="
    }

    json_data = json.dumps(response).encode("utf-8")

    packet = b""
    packet += send_varint(0x00)
    packet += send_varint(len(json_data))
    packet += json_data

    client_socket.sendall(send_varint(len(packet)) + packet)

def log_hit(ip_address, port_num):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    location_isp = lookup_ip(ip_address)
    country = location_isp.get("country")
    isp = location_isp.get("isp")
    connection = (
        f'[{timestamp}] Ping from: `{ip_address}:{port_num}`\n'
        f'Country: {country}\n'
        f'ISP: {isp}'
    )
    print(connection)
    with open(logs, "a") as f:
        f.write(f"[{timestamp}] Ping from: `{ip_address}:{port_num}`\nCountry: {country}\nISP: {isp}\n")
    with open(pureiplogs, "a") as f:
        f.write(f"{ip_address}\n")
    if webhook_url:
        send_discord_message(webhook_url, connection)

def run_honeypot(host='0.0.0.0', port=25565):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        
        print('Honeypot started')
        if webhook_url:
            send_discord_message(webhook_url, ' **Honeypot started**')
        print("waiting for scanners ;)\n")

        while True:
            client_socket, client_address = server_socket.accept()
            ip_address = client_address[0]
            port_num = client_address[1]
            now = time.time()

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
                    send_discord_message(webhook_url, f"**Login attempt from: `{username}` `{ip_address}`**")
                    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    with open(logs, "a") as f:
                        f.write(f"[{timestamp}] Login attempt from: {username} {ip_address}\n")
                    with open(pureiplogs, "a") as f:
                        f.write(f"{ip_address} (login attempt)\n")
                      
                    # if somebody tries to login they will see this message, you can customize it to whatever you want
                    reason = json.dumps({"text": "minescan.xyz honeypot caught your scanner ;)", "color": "yellow"})
                    reason_encoded = reason.encode("utf-8")
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
with open(logs, "a") as f:
    f.write(f"[{timestamp}] Honeypot started.\n")

run_honeypot()
