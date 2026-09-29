import nmap
'''
scanner = nmap.PortScanner()

target = "127.0.0.1"

scanner.scan(
    target,
    "20-100"
)

print(scanner.all_hosts())
print(scanner[target].all_protocols())
print(scanner[target]["tcp"])
'''

def main():
    # 1. Ask for target
    target = input("Target host: ").strip()

    if not target:
        print("Error: Target cannot be empty.")
        return

    # 2. Ask for start and end port
    try:
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))

    # 3. Validate input
    except ValueError:
        print("Error: Ports must be valid numbers.")
        return

    if start_port < 1 or start_port > 65535:
        print("Error: Start port must be between 1 and 65535.")
        return

    if end_port < 1 or end_port > 65535:
        print("Error: End port must be between 1 and 65535.")
        return

    if start_port > end_port:
        print("Error: Start port must be less than or equal to end port.")
        return

    # Limit the scan range
    max_ports = 1000

    if end_port - start_port + 1 > max_ports:
        print(f"Error: You can scan a maximum of {max_ports} ports at once.")
        return

    # Create Nmap scanner
    scanner = nmap.PortScanner()

    port_range = f"{start_port}-{end_port}"

    print(f"\nScanning {target} ports {port_range}...")
    print("-" * 50)

    # 4. Perform scan using python-nmap
    try:
        scanner.scan(
            target,
            port_range,
            arguments="-sT -sV"
        )

    except nmap.PortScannerError as error:
        print(f"Scan error: {error}")
        return

    except Exception as error:
        print(f"Unexpected error: {error}")
        return

    # Check whether the target was found
    if target not in scanner.all_hosts():
        print("No scan results were returned.")
        return

    # 5. Display discovered ports
    found_ports = []

    for host in scanner.all_hosts():

        print(f"Target: {host}")
        print(f"State: {scanner[host].state()}")
        print()

        if "tcp" in scanner[host]:
            for port in sorted(scanner[host]["tcp"]):

                # 6. Display state
                state = scanner[host]["tcp"][port]["state"]

                # 7. Display service information
                service = scanner[host]["tcp"][port].get("name", "")
                product = scanner[host]["tcp"][port].get("product", "")
                version = scanner[host]["tcp"][port].get("version", "")

                found_ports.append(port)

                print(f"Port:    {port}")
                print(f"State:   {state}")
                print(f"Service: {service or 'Unknown'}")

                if product:
                    print(f"Product: {product}")

                if version:
                    print(f"Version: {version}")

                print("-" * 50)

    # 9. Clear result when no ports are discovered
    if not found_ports:
        print("No ports were discovered in the specified range.")


if __name__ == "__main__":
    main()