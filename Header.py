import struct


class Header:
    def __init__(self, header):
        (self.id_, self.flags, self.question_count, self.answer_count,
         self.auth_count, self.additional_count) = struct.unpack('!6H', header)
        self.data = header

        self.qr = self.flags >> 15
        self.op_code = (self.flags & 0b1111 << 11) >> 11
        self.aa = (self.flags & 0b1 << 10) >> 10
        self.tc = (self.flags & 0b1 << 9) >> 9
        self.rd = (self.flags & 0b1 << 8) >> 8

    def encode(self):
        return self.data
