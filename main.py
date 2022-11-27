import socket
from os import popen
import re
import ipaddress

PING_TIMEOUT = 0.01
IGNORE_LIST = ['10.0.2.2', '10.0.2.3']
VERBOSE = False
WELL_KNOWN_PORTS = {
    20: "FTP(data)",
    21: "FTP(control)",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS"
}

'''
Pobiera adres IP z interfejsu

Arguments:
    interface_name: nazwa interfejsu z którego ma zostać pobrany adres IP

Returns:
    Adres IP interfejsu
'''
def get_ip_address(interface_name: str = "eth0") -> str:
    ipv4 = popen(f'ip addr show {interface_name}').read()
    return re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}', ipv4).group(0)


'''
Sprawdza czy host jest aktywny poprzez systemowy PING

Arguments:
    ip_addr: adres IP który ma zostać sprawdzony

Returns:
    True: host odpowiedział na PING
    False: brak odpowiedzi od hosta
'''
def ping(ip_addr: str) -> bool:
    res = popen(f'ping -c 1 -W {PING_TIMEOUT} {ip_addr}').read()
    if re.search('1\spackets\stransmitted,\s1', res) is None:
        return False
    else: return True

'''
Dokonuje skanowania hosta przy pomocy biblioteki socket - próbujemy nawiązać połączenie TCP
Arguments:
    ip_addr: adres IP do przeskanowania

Returns:
    Lista zawierająca otwarte porty

'''
def scan_addr(ip_addr: ipaddress.IPv4Address) -> list[int]:
    open_ports = []

    for port in range(1, 65535):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
                if VERBOSE: print(f'Rozpoczynam skanowanie: {ip_addr}:{port}')
                try:
                    soc.connect((str(ip_addr), port))
                except ConnectionRefusedError:
                    continue

                open_ports.append(port)

    return open_ports

def main() -> None:
    (own_ip_addr, mask) = get_ip_address().split('/')
    network = ipaddress.ip_network(f'{own_ip_addr}/{mask}', strict=False)

    hosts_up = []

    for ip_addr in network.hosts():
        if str(ip_addr) != own_ip_addr and ping(ip_addr):
            hosts_up.append(ip_addr)
            
    for ip_addr in hosts_up:
        if str(ip_addr) in IGNORE_LIST:
            continue
        print(f'\nRozpoczynam skanowanie: {ip_addr}')
        res = scan_addr(ip_addr)

        print(f'Skanowanie zakonczone!\nOtwartych portów: {len(res)}')

        for port in res:
            print(f'{port} {WELL_KNOWN_PORTS.get(port, "")}')

if __name__ == "__main__":
    main()