
import sys
import ipaddress
import socket
from scapy.all import IP, TCP, sr1


if len(sys.argv) != 3:
    print(f"Use mode: python3 {sys.argv[0]} <target> <port>")
    sys.exit(1)

target = sys.argv[1]
portString = sys.argv[2]

try:
    port = int(portString)
except ValueError:
    print("Erro: a porta deve ser um número inteiro.")
    sys.exit(1)

if not 1 <= port <= 65535:
    print("Erro: a porta deve estar entre 1 e 65535.")
    sys.exit(1)

try:
    ipaddress.ip_address(target)
    print(f"IP válido: {target}")

except ValueError:
    try:
        socket.getaddrinfo(
            target,
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP
        )
        print(f"Hostname válido e resolvível: {target}")

    except socket.gaierror:
        print(f"Erro: '{target}' não é um IP válido nem um Hostname resolvível.")
        sys.exit(1)

print(f"Porta TCP: {port}")
print(f"Alvo de destino: {target}")

pacote = IP(dst=target) / TCP(
    dport=port,
    flags="S"
)

resposta = sr1(pacote, timeout=3, verbose=0)

if resposta is None:
    print("Nenhuma resposta recebida.")
elif resposta.haslayer(TCP):
    flags = resposta[TCP].flags
    print(f"Resposta recebida: flags={flags}")

    if flags & 0x12 == 0x12:
        print("SYN-ACK: porta provavelmente aberta.")
    elif flags & 0x04:
        print("RST: porta fechada ou conexão recusada.")
else:
    print("Resposta recebida, mas não é um pacote TCP.")