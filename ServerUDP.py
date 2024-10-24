import socket

from DNSResolver import DNSResolver
from DNSMessage import DNSMessage


class UDPServer:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.address = ('0.0.0.0', 53)
        self.server.bind(self.address)
        self.dns_resolver = DNSResolver()

    def run(self):
        while True:
            data, address = self.server.recvfrom(4096)
            request = DNSMessage(data)

            if request.queries[0].type == 1 or \
                    request.queries[0].type == 28:
                response = self.dns_resolver.resolve(request.data)
                self.server.sendto(response, address)
