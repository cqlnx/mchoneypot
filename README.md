# MCHoneypot

A simple Python honeypot that mimics a Minecraft server to log scans and connection attempts.

## Features

* Responds to Minecraft status pings
* Logs IP, country, and ISP
* Basic rate limiting per IP
* Optional Discord webhook alerts
* Logs login attempts

## Requirements

* Python 3
* requests module (pip install requests)

## Configuration

Edit in the script:

webhook_url = "your-webhook-here"

max_pings = 5

time_window = 300

## Usage

python honeypot.py

Default bind: 0.0.0.0:25565

## Output

* honeypothits.txt
* honeypotips.txt

## Notes

For logging and research purposes only.
