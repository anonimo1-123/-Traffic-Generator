
import random
from scapy.all import IP, TCP, ICMP, Ether, ARP, sr1, send


def create_packets(ip_dst: str, source_port: int) -> dict:
    #Creacion del diccionario de pilas de protocolos
    return {
        "tcp_syn": IP(dst=ip_dst) / TCP(
            sport=source_port,
            dport=80,
            flags="S",
            seq=1000,
            ack=0,
            options=[('MSS', 1460), ('WScale', 7), ('SAckOK', b'')]
        ),
        "tcp_ack": IP(dst=ip_dst) / TCP(
            sport=source_port,
            dport=80,
            flags="A",
            seq=0,
            ack=0
        ),
        "icmp": IP(dst=ip_dst) / ICMP(),
        "arp": Ether() / ARP(pdst=ip_dst)
    }


def perform_tcp_handshake(ip_dst: str) -> None:
    """Realiza TCP handshake de 3 vías.
    
    """
    port_source_random = random.randint(49152, 65535)
    packet_list = create_packets(ip_dst, port_source_random)
    
    # Enviar SYN y esperar SYN-ACK
    answer = sr1(packet_list["tcp_syn"], timeout=2, verbose=False)
    
    if answer is None:
        print("Error: No se recibió respuesta")
        return
    
    if not hasattr(answer, 'ack'):
        print("Error: Respuesta no contiene ACK")
        return
    
    # Verificar secuencia correcta
    if answer.ack == (packet_list["tcp_syn"]["TCP"].seq + 1):
        packet_list["tcp_ack"]["TCP"].seq = answer.ack
        packet_list["tcp_ack"]["TCP"].ack = answer.seq + 1
        send(packet_list["tcp_ack"], verbose=False)
        print("Handshake completado exitosamente")
    else:
        print("Error: Secuencia ACK incorrecta")


if __name__ == "__main__":
    IP_DESTINATION = "10.234.173.71"
    perform_tcp_handshake(IP_DESTINATION)