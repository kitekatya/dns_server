import socket
import struct


class DNSRequestsMaker:
    @staticmethod
    def make_request(request, address):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.sendto(request, address)
                server.settimeout(5)
                answer, _ = server.recvfrom(4096)
            return answer
        except socket.timeout:
            return None

    @staticmethod
    def set_recursion_zero(request):
        return request[:2] + b'\x00\x00' + request[4:]

    def _get_header(self, prev_id, count_answers=0):
        flags = self._get_flags(is_question=count_answers != 0)
        requests_count = 1
        answers_count = count_answers
        auth_count = 0
        add_count = 0

        return (
                struct.pack('!H', prev_id) +
                flags +
                struct.pack('!4H', requests_count, answers_count,
                            auth_count, add_count)
        )

    @staticmethod
    def _get_flags(is_question):
        qr = '0' if is_question else '1'
        opcode = '0000'
        aa = '0'
        tc = '0'
        rd = '0'
        ra = '0'
        z = '000'
        rcode = '0000'
        flags = f"{qr}{opcode}{aa}{tc}{rd}{ra}{z}{rcode}"
        return struct.pack('!H', int(flags, 2))

    @staticmethod
    def _get_query(request):
        body = DNSRequestsMaker._get_query_body(request)
        request_type = request_class = struct.pack('!H', 1)
        return body + request_type + request_class

    @staticmethod
    def _get_query_body(request):
        domain_parts = request.split('.')
        bytes_request = b''

        for domain_part in domain_parts:
            length = struct.pack('B', len(domain_part))
            bytes_request += length + domain_part.encode('utf-8')
        bytes_request += struct.pack('B', 0)

        return bytes_request

    def make_answers(self, domain, prev_id, *hosts):
        header = self._get_header(prev_id, count_answers=len(hosts))
        question_body = self._get_query(domain)
        answers = self._get_answers(*hosts)
        return header + question_body + answers

    @staticmethod
    def _get_answers(*ip_addresses):
        name = b'\xc0\x0c'
        answer_type = struct.pack('>H', 1)  # Type A
        answer_class = struct.pack('>H', 1)  # Class IN
        ttl = struct.pack('>I', 300)
        answers = b''
        for ip_address in ip_addresses:
            ip_parts = [int(part) for part in ip_address.split('.')]
            ip_packed = struct.pack('BBBB', *ip_parts)
            data_length = struct.pack('>H', len(ip_packed))
            answers += (
                        name + answer_type + answer_class + ttl + data_length + ip_packed)

        return answers
