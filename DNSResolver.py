from math import prod

from Record import Record
from DNSRequestsMaker import DNSRequestsMaker
from DNSMessage import DNSMessage


class DNSResolver:
    def __init__(self):
        self.request_maker = DNSRequestsMaker()

    def resolve(self, request: DNSMessage, host="198.41.0.4"):
        possible_multiply = self.check_dop(request)
        if possible_multiply:
            return possible_multiply

        request.set_recursion_zero()
        response = DNSMessage(self.request_maker.make_request(
            request.data, (host, 53)))

        while not response.header.answer_count:
            if response.header.auth_count == 0: break
            for authority in response.authorities:
                if authority.type == 2:
                    hostname = authority.get_address(response.data)
                    host = DNSMessage.get_auth_server_ipv4(
                        response, hostname)
                    if host is None:
                        intermediate_request = (self.request_maker.get_request(hostname))
                        host = DNSResolver().resolve(DNSMessage(intermediate_request))

                        response1 = DNSResolver().resolve(DNSMessage(
                            intermediate_request))
                        for answer in response1.answers:
                            host = Record.parse_ipv4(answer.address)
                            if host: break


                    response = self.request_maker.make_request(request.data, (host, 53))
                    if response is None: continue
                    response = DNSMessage(response)
                    break
            else:
                break

        return response

    def check_dop(self, request: DNSMessage):
        domain = request.queries[0].name
        id_ = request.header.id_

        if 'multiply' in domain:
            domain_ = domain.split('.')
            domain_ = domain_[:domain_.index('multiply')]
            mult = prod(map(int, domain_)) % 256
            return DNSMessage(self.request_maker.make_answers(domain, id_,
                                                   f'127.0.0.{mult}'))
        else:
            return None
