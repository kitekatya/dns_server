from math import prod

from DNSRequestsMaker import DNSRequestsMaker
from DNSMessage import DNSMessage


class DNSResolver:
    def __init__(self):
        self.request_maker = DNSRequestsMaker()

    def resolve(self, request, host="a.root-servers.net"):
        response = DNSMessage(self.request_maker.make_request(
            request, (host, 53)))
        domain = response.queries[0].name

        possible_multiply = self.check_dop(domain)
        if possible_multiply:
            return possible_multiply

        while not response.header.answer_count:
            if response.header.auth_count == 0: break
            for authority in response.authorities:
                if authority.type == 2:
                    host = authority.get_address(response.data)
                    response = self.request_maker.make_request(
                        request, (host, 53))
                    if response is None: continue
                    response = DNSMessage(response)
                    break

        return response.data

    def check_dop(self, domain: str):
        if 'multiply' in domain:
            domain_ = domain.split('.')
            domain_ = domain_[:domain_.index('multiply')]
            mult = prod(map(int, domain_)) % 256
            return self.request_maker.make_answers(domain, f'127.0.0.{mult}')
        else:
            return None
