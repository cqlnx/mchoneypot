# MCHoneypot

A simple Python honeypot that mimics a Minecraft server to log scans and connection attempts.

---

## Features

- Responds to Minecraft status pings  
- Logs IP, country, and ISP  
- Tracks login attempts (username + IP)  
- Basic per-IP rate limiting  
- Optional Discord webhook alerts  
- Config-driven setup via `config.json`  

---

## Requirements

- Python 3  
- requests module

Install dependencies:

```
pip install -r requirements.txt
```

---

## Configuration (`config.json`)

The honeypot is fully controlled via a config file:

```json
{
  "webhook_url": "",
  "enable_webhook": false,
  "logs": "logs/honeypothits.txt",
  "pureiplogs": "logs/honeypotips.txt",
  "bind_host": "0.0.0.0",
  "port": 25565,
  "max_pings": 5,
  "time_window": 300,

  "response": {
    "version": {
      "name": "1.21.11",
      "protocol": 774
    },
    "players": {
      "max": 20,
      "online": 4,
      "sample": [
        { "name": "Notch", "id": "069a79f4-44e9-4726-a5be-fca90e38aaf5" },
        { "name": "Herobrine", "id": "f84c6a79-0a4e-45e0-879b-cd49ebd4c4e2" },
        { "name": "Dinnerbone", "id": "61699b2e-d327-4a01-9f1e-0ea8c3f06bc6" },
        { "name": "popiiumaa", "id": "6f22dc59-9977-43ba-8699-dcf481600a1c" }
      ]
    },
    "description": {
      "text": "we love honey ;)"
    },
    "favicon": "data:image/png;base64,..."
  },

  "kick_message": {
    "text": "minescan.xyz honeypot caught your scanner ;)",
    "color": "yellow"
  }
}
```

---

## Usage

```
python honeypot.py
```

Default bind:

```
0.0.0.0:25565
```

---

## Output Files

- logs/honeypothits.txt  
- logs/honeypotips.txt  

---

## Notes

For logging and research purposes only.
