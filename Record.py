import struct


class Record:
    def __init__(self, data, full_data):
        self.data = data

        i = self.get_name_length(data)
        self.name = Record.parse_name(self.data[:i], full_data)
        unpack_size = struct.calcsize('!HHIH')

        (self.type, self.class_, self.time, self.data_length) = struct.unpack(
            '!HHIH', self.data[i:i + unpack_size])

        self.length = i + unpack_size + self.data_length
        self.address = self.data[i + unpack_size:self.length]

        self.data = self.data[:self.length]

    def encode(self):
        return self.data

    def get_address(self, data):
        return self.parse_name(self.address, data)

    @staticmethod
    def get_name_length(data):
        for i in range(len(data) - 1):
            if data[i: i + 1] == b"\x00":
                return i + 1
            elif data[i: i + 1] == b"\xc0":
                return i + 2

    @staticmethod
    def parse_name(byte_nameserver, dns_answer):
        parts = Record.get_parts_ns(byte_nameserver, dns_answer)
        decoded_parts = []
        for part in parts:
            decoded_parts.append(part.decode())
        return '.'.join(decoded_parts)

    @staticmethod
    def get_parts_ns(byte_ns, dns_answer):
        parts = []
        current = 0
        while byte_ns[current] != 0:
            if byte_ns[current] == struct.unpack('B', b'\xc0')[0]:
                offset = byte_ns[current + 1]
                ans_by_offset = dns_answer[offset:]
                ans_by_offset = ans_by_offset[:ans_by_offset.find(b'\x00') + 1]
                parts += Record.get_parts_ns(ans_by_offset, dns_answer)
                break
            part_length = byte_ns[current]
            parts.append(byte_ns[current + 1: current + 1 + part_length])
            current += 1 + part_length
        return parts
