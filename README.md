# Secure-Relay-Based-Chat-System
The Secure Relay-Based Chat System ensures multiple clients communicate security through a central relay server. 

Terminal 1:
python run_relay.py

Terminal 2:
python ./tools/mitm_proxy.py

Terminal 3:
python run_client.py Alice --relay-port 5001

Terminal 4:
python run_client.py Bob

Session setup (Terminal 3):
session Bob

Send encrypted message (Terminal 3):
send Bob SecretMessage

Proxy commands (Terminal 2):
s (show captured message)
r (replay message)
t (tamper message)
c (clear buffer)