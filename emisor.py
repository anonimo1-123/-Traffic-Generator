from scapy.all import *
from package_creation import *
target = "45.33.32.156"
port = 4800
get_raw = bytearray(
    "GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\n\r\n ", encoding="utf-8"
)

"""
    The function `filter_http_ok` checks if a packet contains an HTTP response with status code 200 OK.
"""

def filter_http_ok(packet:scapy)->bool:
    if packet.haslayer(Raw):
        if b"HTTP/1.1 200 OK" in packet[Raw].load :
            return True
    

def create_packet(tuple_protocols_packet:tuple):
    pass
    




try:
    IP_packet = IP(dst=target) / TCP(
        sport=port, flags="S", window=65495, options=[("MSS", 1460)]
    )
    answer = sr1(IP_packet)

    values = {
        "flag": answer.payload.flags,
        "seq": answer.payload.ack,
        "ack": answer.payload.seq + 1,
    }

    if values["flag"] == "SA":
        confirmation_syn = IP(dst=target) / TCP(
            sport=port, flags="A", seq=values["seq"], ack=values["ack"]
        )
    send(confirmation_syn)

    request_get = (
        IP(dst=target)
        / TCP(sport=port, dport=80, flags="A", seq=values["seq"], ack=values["ack"])
        / get_raw
    )
    send(request_get)
    while True:
        print("********************************************")
        packet = sniff(filter="tcp port 80",lfilter=filter_http_ok ,iface="wlp3s0", count=1)
        
except KeyboardInterrupt:
    print("termino el programa")
