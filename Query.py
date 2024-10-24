import struct


class Query:
    def __init__(self, data):
        self.data = data
        self.length = 0

        i = self.data.find(0) + 1
        self.name = Query.bytes_to_domain(self.data[:i])
        self.type, self.class_ = struct.unpack('!HH', self.data[i:i + 4])
        self.length = i + 4
        self.data = self.data[:self.length]

    def encode(self):
        return self.data

    @staticmethod
    def bytes_to_domain(byte_data):
        parts = []
        i = 0

        while i < len(byte_data):
            length = byte_data[i]
            if length == 0:
                break
            i += 1
            part = byte_data[i:i + length].decode('utf-8')
            parts.append(part)
            i += length

        return '.'.join(parts)
