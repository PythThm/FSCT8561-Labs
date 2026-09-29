import socket

# Code without function
'''
TARGET = "127.0.0.1"
PORT = 80

scanner_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

scanner_socket.settimeout(0.5)

result = scanner_socket.connect_ex(
    (TARGET, PORT)
)

if result == 0:
    print("Port", PORT, "is OPEN")
else:
    print("Port", PORT, "is not open")

scanner_socket.close()
'''

# Code with function in mind, messy
'''
def scan_port(target, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    socket.setdefaulttimeout(0.5)

    result = sock.connect_ex(
        (target, port)
    )

    sock.close()

    if result == 0:
        return True
    else:
        return False

target = input("Target host IP: ")
start_port = int(input("Start port: "))
end_port = int(input("End port: "))

max_port = 1000

if start_port < 1 or start_port > 65535:
    print("Invalid start port. Port must be between 1 and 65535.")
elif end_port < 1 or end_port > 65535:
    print("Invalid end port. Port must be between 1 and 65535.")
elif start_port > end_port:
    print("Invalid port range. Start port must be less than or equal to end port.")
elif end_port - start_port + 1 > max_port:
    print(f"Port range is too large. You can scan a maximum of {max_port} ports at once.")
else:
    open_port = []
    for port in range(start_port, end_port + 1): 
        if scan_port(target, port):
            open_port.append(port)

    print("Open ports:", open_port)
'''

# Real deal
def scan_port(target, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    try:
        sock.settimeout(0.5)

        result = sock.connect_ex(
            (target, port)
        )

        return result == 0 # if 0 returns true

    finally:
        socket.close

try:
    target = input("Target Host: ") # prompt for host

    try:
        target_ip = socket.gethostbyname(target) # resolve for hostname ip
        print(f"Resolved {target} to {target_ip}")

    except socket.gaierror:
        print("Bad hostname or IP addr")
        exit() # gn to the resolve for hostname

    start_port = int(input("Start Port: ")) # prompt for ports
    end_port = int(input("End Port: "))
    max_port = 1000

    if start_port < 1 or start_port > 65535:
        print("Invalid start port. Port must be between 1 and 65535.")
    elif end_port < 1 or end_port > 65535:
        print("Invalid end port. Port must be between 1 and 65535.")
    elif start_port > end_port:
        print("Invalid port range. Start port must be less than or equal to end port.")
    elif end_port - start_port + 1 > max_port:
        print(f"Port range is too large. You can scan a maximum of {max_port} ports at once.")
    else: # Real deal
        open_port = [] # adding to open port list if found any
        for i in range(start_port, end_port + 1):
            if scan_port(target_ip, i):
                open_port.append(i)

        if open_port: # when list aint empty
            print("\nOpen ports: ")

            for i in open_port:
                try:
                    service = socket.getservbyport(i, "tcp") # i as port, specify tcp 
                except OSError: # handler if service is returned as error
                    service = "unknown"
                print(f"Port {i}: {service}")
        else:
            print("\nNo open ports detected")

except ValueError: # invalid input handle crash
    print("bad imput, please be smart and type in numbers")
except KeyboardInterrupt:
    print("\nNot doing scan anymore")