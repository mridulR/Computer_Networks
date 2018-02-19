import sys
import time
import dns
import dns.name
import dns.query
import dns.dnssec
import dns.resolver
from dns.exception import DNSException

root_servers = [
            '198.41.0.4',
            '199.9.14.201',
            '192.33.4.12',
            '199.7.91.13',
            '192.203.230.10',
            '192.5.5.241',
            '192.112.36.4',
            '198.97.190.53',
            '192.36.148.17',
            '192.58.128.30',
            '193.0.14.129',
            '199.7.83.42',
            '202.12.27.33'
        ]


message_size = 0

# This function takes in the domain and server as function parameters.
# This function is used for building chain of trust.
# It returns the DS and Algorithm.
def resolve_component_parent(domain_search, server):
    global message_size
    result = []
    ds = None
    algorithm = -1
    try:
        query = dns.message.make_query(domain_search,
                                       dns.rdatatype.DNSKEY,
                                       want_dnssec=True)
        response = dns.query.tcp(query, server, timeout=1)
        message_size += sys.getsizeof(response)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            return (None, None, None)

        # Extract DS and Algorithm from the authority section of the response.
        if len(response.authority) > 0:
            for rrset in response.authority:
                rr = rrset[0]
                if rrset.rdtype == dns.rdatatype.DS:
                    ds = rr
                    algorithm = rr.digest_type

            rrset = response.authority[0]
        else:
            rrset = response.answer[0]

        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            result.append(server)
        elif len(response.answer) > 0:
            result.append(server)
        else:
            authority = rr.target.to_text()
            if len(response.additional) > 0:
                rrset = response.additional
                for rr in rrset:
                    result.append(rr[0].to_text())
            else:
                result = get_domain_servers(authority)

    except Exception:
        return None, None, None

    return result, ds, algorithm

# Query for DNSKEY and RRSIG(DNSKEY) from the child server.
# This data is used for verifying chain of trust.
# Also used for verifying the DNSKEY of the child server.
def resolve_component_child(domain_search, server):
    dnskey = None
    rrsig_dnskey = None
    dnskey_record = None
    try:
        query = dns.message.make_query(domain_search,
                                       dns.rdatatype.DNSKEY,
                                       want_dnssec=True)
        response = dns.query.tcp(query, server, timeout=1)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                raise Exception('Error in response')

        if len(response.answer) > 0:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    dnskey_record = rrset
                    for r in rrset:
                        if r.flags == 257:
                            dnskey = r
                elif rrset.rdtype == dns.rdatatype.RRSIG:
                    rrsig_dnskey = rrset

    except Exception:
        return None, None, None

    return dnskey, rrsig_dnskey, dnskey_record

# Validate the root server.
# Static chain of trust test is done.
# DNSKEY verification done by querying for '.' against the root server.
def validate_root_server(server):
    ds1 = '19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5'
    ds2 = '20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D'

    (dnskey, rrsig_dnskey, dnskey_record) = resolve_component_child('.', server)
    if not dnskey:
        return False

    hash_key = dns.dnssec.make_ds('.', dnskey, 'sha256')
    if str(hash_key) == ds1.lower() or str(hash_key) == ds2.lower():
        name = dns.name.from_text('.')
        try:
            dns.dnssec.validate(dnskey_record, rrsig_dnskey, {name: dnskey_record})
        except dns.dnssec.ValidationFailure:
            print('DNSSEC verification failed')
            return False
        return True
    else:
        return False

def get_tld_server_details(tld_domain):
    result = None
    ds = None
    algorithm = -1
    for root_server in root_servers:
        try:
            if validate_root_server(root_server):
                (result, ds, algorithm) = resolve_component_parent(tld_domain, root_server)
            if result:
                break
        except:
            # Try other root server
            pass
    return (result, ds, algorithm)


# Starting from root dns, this method finally resolves dns level by level.
# However, its different from non-secure dns in its implementation.
def get_domain_servers(domain):
    domain = dns.name.from_text(domain)
    sub_domains = str(domain).split('.')
    sub_domains = list(reversed(sub_domains))
    search_domain = sub_domains[1] + '.'
    servers = None
    algorithm = None
    ds = None 
    (servers, ds, algorithm) = get_tld_server_details(search_domain)
    if not servers:
        return None

    root_index = 0

    domain_parts = str(domain).split('.')

    del domain_parts[-1]
    domain_search = domain_parts[-1] + '.'


    del domain_parts[-1]
    domain_parts = ['@'] + domain_parts
    for part in reversed(domain_parts):
        server_index = 0
        result = None
        dnskey = None
        rrsig_dnskey = None

        # Query for the DNSKEY and RRSIG(DNSKEY) from the child server.
        # If DNSKEY or RRSIG(DNSKEY) does not exist, it mean DNSSEC is not supported.
        while not dnskey or not rrsig_dnskey:
            (dnskey, rrsig_dnskey, dnskey_record) = resolve_component_child(domain_search, servers[server_index])
            server_index += 1
            if server_index == len(servers):
                print("DNSSEC not supported")
                return None

        # Check for chain of trust between parent and child.
        # For this we are creating DS from child's DNSKEY and compare it against DS from parent.
        # If anything fails in this step, it means that DNSSEC verification failed.
        if algorithm and ds and dnskey and rrsig_dnskey:
            if algorithm == 1:
                algorithm = 'sha1'
            else:
                algorithm = 'sha256'
            hash_key = dns.dnssec.make_ds(domain_search, dnskey, algorithm)
            if hash_key != ds:
                print("DNSSEC verification failed")
                return None

            name = dns.name.from_text(domain_search)
            try:
                dns.dnssec.validate(dnskey_record, rrsig_dnskey, {name: dnskey_record})
            except dns.dnssec.ValidationFailure:
                print('DNSSEC verification failed')
                return None
        else:
            print("DNSSEC not supported")
            return None

        if part == '@':
            break

        domain_search = part + '.' + domain_search
        while not result:
            try:
                # Query for the DS, Algorithm and nameserver address from the server.
                # This will be used later for verifying chain of trust.
                (result, ds, algorithm) = resolve_component_parent(domain_search, servers[server_index])
                if result:
                    servers = result
                else:
                    raise Exception('Result Empty')
            except Exception:
                server_index += 1
                if server_index == len(servers):
                    return None

    return servers


def resolve_domain_category(domain, category):
    global message_size
    query = dns.message.make_query(domain, category)
    response = None
    servers = get_domain_servers(domain)
    if servers:
        for server in servers:
            try:
                response = dns.query.tcp(query, server, timeout=1)
                message_size += sys.getsizeof(response)
            except:
                # try with another server
                pass
            if response:
                break
    return response

# If CNAME comes, exception is thrown and its retried for new domain with same category
# recursively. Else record type is printed.
def format_result(result, domain, category):
    if result:
        qname = dns.name.from_text(domain)
        try:
            if category == "A":
                sol = result.find_rrset(result.answer, qname, dns.rdataclass.IN, dns.rdatatype.A)
            if category == "NS":
                sol = result.find_rrset(result.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
            if category == "MX":
                sol = result.find_rrset(result.answer, qname, dns.rdataclass.IN, dns.rdatatype.MX)
            for ans in result.answer:
                print(ans)

        except KeyError:
            # Exception occurs for CNAME and has one entry
            if len(result.answer) > 0:
                print(result.answer[0])
                new_domain = result.answer[0].items[0].target.to_text()
                format_result(resolve_domain_category(new_domain, category), new_domain, category)

if __name__ == '__main__':
    
    category = 'A' 
    domain = sys.argv[1]
    if len(sys.argv) > 2:
        category = sys.argv[2]

    if domain:
        start_time = int(round(time.time() * 1000))
        result = resolve_domain_category(domain, category)
        if result:
            print()
            print('QUESTION SECTION:')
            for ques in result.question:
                print(ques)
            print()
            print('ANSWER SECTION:')
            format_result(result, domain, category)
            print()
            print("Query Time: " + str(int(round(time.time() * 1000)) - start_time) + " msec")
            print("WHEN: " + str(time.strftime("%c")))
            print("MSG SIZE rcvd : " + str(message_size))
            print()
    else:
        print("Domain cannot be empty") 
