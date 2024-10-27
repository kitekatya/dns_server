from Header import Header
from Query import Query
from Record import Record


class DNSMessage:
    def __init__(self, data: bytes):
        self.data = data
        self.header: Header = Header(data[:12])
        self.queries, byte_index = self.get_queries()
        self.answers, byte_index = self.get_records(byte_index,
                                                    self.header.answer_count)
        self.authorities, byte_index = self.get_records(byte_index,
                                                        self.header.auth_count)
        self.additional, byte_index = self.get_records(byte_index,
                                                       self.header.additional_count)

    def set_recursion_zero(self):
        self.header.set_recursion_zero()
        self.data = self.header.data + self.data[12:]

    def get_queries(self):
        queries = []
        byte_index = 12
        for i in range(self.header.question_count):
            query = Query(self.data[byte_index:])
            queries.append(query)
            byte_index += query.length
        return queries, byte_index

    def get_records(self, byte_index, count):
        records = []
        for i in range(count):
            record = Record(self.data[byte_index:], self.data)
            records.append(record)
            byte_index += record.length

        return records, byte_index

    @staticmethod
    def get_auth_server_ipv4(dns_response, auth_server):
        for additional in dns_response.additional:
            if additional.type == 1 and additional.name == auth_server:
                return Record.parse_ipv4(additional.address)
