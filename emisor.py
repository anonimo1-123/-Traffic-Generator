
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
        "arp": Ether() / ARP(pdst=ip_dst),
        "get_http_request": IP(dst=ip_dst)/TCP()/(
            "GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"
            "Accept-Language: es-ES,es;q=0.9,en;q=0.8\r\n"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Connection: keep-alive\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Cache-Control: max-age=0\r\n"
            "\r\n" )        
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
        perform_flow_http()
    
    else:
        print("Error: Secuencia ACK incorrecta")
        
        
def perform_flow_http()->bool:
    pass
    


if __name__ == "__main__":
    IP_DESTINATION = "destination_ip"
    perform_tcp_handshake(IP_DESTINATION)