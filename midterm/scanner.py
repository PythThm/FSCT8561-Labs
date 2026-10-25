import nmap

from protocol import SERVER_PORT

TARGET = "127.0.0.1"
MAX_PORTS = 1000          # same cap from the lab 
SMALL_RANGE = 10          # ranges up to this size print the state of every port
NMAP_ARGUMENTS = "-sT -sV"    # TCP connect scan + service/version detection 
SCAN_TIMEOUT = 120        # time before the scan is abandoned


def _validate_range(start_port, end_port):
    """Return (start, end) as ints, or raise ValueError with a user-facing message."""
    try:
        start, end = int(start_port), int(end_port)
    except (TypeError, ValueError):
        raise ValueError("Ports must be valid numbers.")
    if not 1 <= start <= 65535:
        raise ValueError("Start port must be between 1 and 65535.")
    if not 1 <= end <= 65535:
        raise ValueError("End port must be between 1 and 65535.")
    if start > end:
        raise ValueError("Start port must be less than or equal to end port.")
    if end - start + 1 > MAX_PORTS:
        raise ValueError(f"You can scan a maximum of {MAX_PORTS} ports at once.")
    return start, end


def run_port_scan(start_port, end_port, target=TARGET):
    """
    Scan start_port..end_port on localhost and print the results.
    Returns a list of dicts (port, state, service, product, version), or None on error.
    """
    if target != TARGET:
        print(f"Error: only {TARGET} may be scanned.")
        return None

    try:
        start, end = _validate_range(start_port, end_port)
    except ValueError as problem:
        print(f"Error: {problem}")
        return None

    port_range = f"{start}-{end}"
    print(f"\nScanning {TARGET} ports {port_range}...")
    print("-" * 50)

    try:
        scanner = nmap.PortScanner()   # raises PortScannerError if nmap is not installed
        scanner.scan(TARGET, port_range, arguments=NMAP_ARGUMENTS, timeout=SCAN_TIMEOUT)
    except nmap.PortScannerTimeout:
        print("Scan error: the scan timed out.")
        return None
    except nmap.PortScannerError as problem:
        print(f"Scan error: {problem}")
        return None
    except Exception as problem:
        print(f"Unexpected error: {problem}")
        return None

    if TARGET not in scanner.all_hosts():
        print("No scan results were returned.")
        return None

    listed = scanner[TARGET].get("tcp", {})
    results = []
    for port in range(start, end + 1):
        info = listed.get(port)
        if info is None:
            # Nmap did not list it: closed or filtered. Show it only for small ranges.
            if end - start + 1 <= SMALL_RANGE:
                results.append({"port": port, "state": "closed/filtered", "service": "",
                                "product": "", "version": ""})
            continue
        results.append({
            "port": port,
            "state": info.get("state", ""),
            "service": info.get("name", ""),
            "product": info.get("product", ""),
            "version": info.get("version", ""),
        })

    for item in results:
        print(f"Port:    {item['port']}")
        print(f"State:   {item['state']}")
        # Nmap guesses a service name from the port number even for closed ports,
        # which would be misleading, so service details are shown for open ports only.
        if item["state"] == "open":
            print(f"Service: {item['service'] or 'Unknown'}")
            if item["product"]:
                print(f"Product: {item['product']}")
            if item["version"]:
                print(f"Version: {item['version']}")
        print("-" * 50)

    open_ports = [r for r in results if r["state"] == "open"]
    if not results:
        print("No ports were discovered in the specified range.")
    if end - start + 1 > SMALL_RANGE:
        print("Ports in the range that are not listed above are closed or filtered.")
    print(f"Open ports found: {len(open_ports)}")
    if start <= SERVER_PORT <= end:
        found = any(r["port"] == SERVER_PORT for r in open_ports)
        print(f"Sentinel server port {SERVER_PORT}: {'OPEN' if found else 'not open (is server.py running?)'}")
    return results