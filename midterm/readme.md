# Operation Sentinel
* **Server** (`server.py`): TCP service with password + TOTP login. Additional PCAP analysis after authentication
* **Client** (`client.py`): menu, login, port scan and HTTP check .

The port scanner and HTTP checker are Python modules imported by `client.py`. They are not services. Only the PCAP analysis crosses the TCP link.

Everything is restricted to `127.0.0.1`. Do not point it at other systems.

## Files
`client.py`: user inputs
`scanner.py`: Port scanner 
`http_checker.py`: HTTP security checks 
`server.py`: Listener and dispatcher 
`auth_session.py`: Password check , TOTP, session state
`pcap_analyzer.py`: PCAP summary and Scapy stuff
`security_log.py`: Security event log 
`protocol.py`: Shared length-prefixed framing 
`setup_users.py`: basically creating a simple DB

## Steps
1. Python 3.10+ and nmap installed 
2. `pip install -r requirements.txt`
3. Ensure you have `FSCT8561_Operation_Sentinel_Traffic.pcap` and `test_website.py`
4. Create the user (once): `python setup_users.py` and follow the instructions given 
5. Run (three terminals)
```
python test_website.py     # terminal 1: local test website on 127.0.0.1:8765
python server.py           # terminal 2: Sentinel server on 127.0.0.1:5050
python client.py           # terminal 3: analyst client
```

## Using the client
Log in with the username, password, and the 6-digit code from the authenticator app. Then:
1. **Scan local TCP ports.** Try `5050`-`5050` (open: the Sentinel server) and `5051`-`5051` (closed). Ranges are capped at 1000 ports.
2. **Check the test website.** Writes `http_scan_results.csv` and `http_findings.csv`.
3. **Analyze the PCAP** on the server.
4. **Send a diagnostic message** (1-200 characters).
5. **Exit.**

## Testing
1. Authentication required: Send PCAP before logging in. Expected response: ERROR|AUTH_REQUIRED.
2. Failed login: Test incorrect passwords and OTP codes. Three failures close the connection; five failures for a username trigger a 60-second lockout.
3. Port scanning: Test open port 5050 and closed port 5051.
4. HTTP connection failure: Stop test_website.py and run the HTTP check. It should report that the target is unreachable.
5. Server disconnect: Stop server.py while the client is connected and test error handling.
6. Invalid input: Try letters as port numbers, port 0, a start port greater than the end port, and empty or 201-character messages.
7. Security logging: Check security_events.log to confirm that passwords and OTP codes are not recorded.