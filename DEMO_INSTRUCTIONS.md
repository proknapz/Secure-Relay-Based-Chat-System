# Secure Relay-Based Chat System - Demo Instructions (Proxy Version)

Follow these steps to demonstrate the security features using a Man-in-the-Middle (MITM) Proxy.

## Prerequisites
Open 4 separate terminal windows.

## Step 1: Start the Relay Server
In Terminal 1, run:

python run_relay.py

Server starts on port 6000 (default).

## Step 2: Start the MITM Proxy
In Terminal 2, run:

python tools/mitm_proxy.py


Proxy listens on port 5001.
Proxy forwards to port 6000.


## Step 3: Start Client Alice (Connected to Proxy)
In Terminal 3, run:

python run_client.py Alice --relay-port 5001


Alice connects to the **Proxy** (port 5001).
Proxy logs "Client connected" and "Connected to relay".
Alice registers and authenticates successfully (traffic flows through proxy).

## Step 4: Start Client Bob (Connected to Relay)
In Terminal 4, run:

python run_client.py Bob

## Step 5: Establish Session
In Terminal 3 (Alice), run:

session Bob

Session established. Proxy logs `>> Forwarding SESSION_REQUEST`, etc.

## Step 6: Demonstrate Encryption
In Terminal 3 (Alice), run:

send Bob SecretMessage


Bob receives "SecretMessage".

Logs `>> Captured ENCRYPTED_MESSAGE`.
Type `s` in the Proxy terminal.
Observe the JSON output. The `ciphertext` is random characters, proving the proxy cannot read "SecretMessage".

## Step 7: Demonstrate Replay Protection
The proxy has captured the last encrypted message ("SecretMessage").

r

Logs `✗ Replay detected! Seq X <= Y`.
The message is rejected and Bob continues listening normally.
Send a new message from Alice - it should work perfectly!

## Step 8: Demonstrate Integrity / Tampering Protection

t

Logs `✗ Invalid HMAC for message` (tampering detected).
Uses a unique sequence number, so always shows HMAC failure.
Send a new message from Alice - it should work perfectly!


