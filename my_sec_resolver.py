import sys
import time
import dns
import dns.name
import dns.query
import dns.dnssec
import dns.resolver

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

ROOT_DS_1 = "19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"
ROOT_DS_2 = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

message_size = 0

# https://newsletter.dnsimple.com/dnssec-record-types-part-two/
def get_parent_zone_details(domain_search, server):
    global message_size
    servers = []
    ds_record = None
    hash_algo = -1
    try:
        query = dns.message.make_query(domain_search, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.tcp(query, server, timeout=1)
        message_size += sys.getsizeof(response)

        #print("Response - " + str(response))

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            return None, None, None

        # If authority has SOA return, else set ds_record and algo
        if len(response.authority) > 0:
            for auth_record in response.authority:
                if auth_record.rdtype == dns.rdatatype.DS:
                    ds_record = auth_record[0]
                    hash_algo = auth_record[0].digest_type

            if response.authority[0][0] == dns.rdatatype.SOA:
                servers.append(server)
                return servers, ds_record, hash_algo

        # if answer is found, return
        if len(response.answer) > 0:
            servers.append(server)
            return servers, ds_record, hash_algo

        authority = response.authority[0][0].target.to_text()
        if len(response.additional) > 0:
            for rr in response.additional:
                 servers.append(rr[0].to_text())
        else:
            servers = get_domain_servers(authority)
            
    except Exception:
        return None, None, None

    return servers, ds_record, hash_algo

# https://newsletter.dnsimple.com/dnssec-record-types/
# @TODO : Bug while traversing response, Fix it
def extract_zsk_rrsig_rrset(response):
    ZSK = None
    RRSIG = None
    RRset = None

    print(response)

    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            RRset = rrset
            for record in rrset:
                if record.flags == 257:
                    ZSK = record
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            RRSIG = rrset
        else:
            pass
    return (ZSK, RRSIG, RRset)

# https://newsletter.dnsimple.com/dnssec-record-types/
def get_child_zone_details(domain_search, server):
    ZSK = None
    RRSIG = None
    RRset = None
    try:
        query = dns.message.make_query(domain_search, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.tcp(query, server, timeout=1)
        #print(response)

        if response.rcode() != dns.rcode.NOERROR and response.rcode() == dns.rcode.NXDOMAIN:
            return None, None, None

        if len(response.answer) > 0:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    RRset = rrset
                    for record in rrset:
                        if record.flags == 257:
                            ZSK = record
                elif rrset.rdtype == dns.rdatatype.RRSIG:
                    RRSIG = rrset
                else:
                    pass

    except Exception:
        return None, None, None

    return ZSK, RRSIG, RRset

# https://serverfault.com/questions/584570/can-i-reasonably-use-sha-256-in-a-dnssec-deployment
# only validation with sha-256 is required for root servers
def validate_root_server(server):
    (ZSK, RRSIG, RRset) = get_child_zone_details('.', server)
    if not ZSK and not RRSIG and not RRset:
        return False

    digest = dns.dnssec.make_ds('.', ZSK, 'sha256')
    if str(digest) == ROOT_DS_1.lower() or str(digest) == ROOT_DS_2.lower():
        try:
            dns.dnssec.validate(RRset, RRSIG, {dns.name.from_text('.'): RRset})
        except dns.dnssec.ValidationFailure:
            print('DNSSEC verification failed')
            return False
        return True
    else:
        return False

def get_tld_server_details(tld_domain):
    servers = None
    ds_record = None
    hash_algo = -1
    for root_server in root_servers:
        try:
            if validate_root_server(root_server):
                (servers, ds_record, hash_algo) = get_parent_zone_details(tld_domain, root_server)
            if servers:
                break
        except:
            # Try other root server
            pass
    return (servers, ds_record, hash_algo)

def verify_dnssec(algo, ds_record, dnskey, rrsig_dnskey, dnskey_record, search_domain):
    if algo and ds_record and dnskey and rrsig_dnskey:
        if algo == 1:
            algo = 'sha1'
        else:
            algo = 'sha256'
        if dns.dnssec.make_ds(search_domain, dnskey, algo) != ds_record:
            print("DNSSEC verification failed")
            return False

        try:
            dns.dnssec.validate(dnskey_record, rrsig_dnskey, {dns.name.from_text(search_domain): dnskey_record})
            return True
        except dns.dnssec.ValidationFailure:
            print('DNSSEC verification failed')
            return False
    else:
        print("DNSSEC not supported")
        return False


def get_validate_dnssec_support(search_domain, servers, algo, ds_record):
    ZSK = None
    RRSIG = None
    RRset = None
    index = 0
    while not ZSK or not RRSIG:
        if index == len(servers):
            break
        ZSK, RRSIG, RRset = get_child_zone_details(search_domain, servers[index])        
        index = index + 1

    if index == len(servers):
        print("DNSSEC not supported")
        return index, ZSK, RRSIG, RRset

    if not verify_dnssec(algo, ds_record, ZSK, RRSIG, RRset, search_domain):
        return len(servers), ZSK, RRSIG, RRset
    return index, ZSK, RRSIG, RRset        

def parse_doamin(domain):
    domain = dns.name.from_text(domain)
    sub_domains = str(domain).split('.')
    return list(reversed(sub_domains))


# Starting from root dns, this method finally resolves dns level by level.
# However, its different from non-secure dns in its implementation.
def get_domain_servers(domain):
    sub_domains = parse_doamin(domain)
    search_domain = sub_domains[1] + '.'
    servers = None
    hash_algo = None
    ds_record = None 
    (servers, ds_record, hash_algo) = get_tld_server_details(search_domain)
    
    if not servers:
        return None
    
    for ind in range(2, len(sub_domains)):
        current_domain = sub_domains[ind]
        next_level_servers = None
        dnskey = None
        rrsig_dnskey = None

        ind, dnskey, rrsig_dnskey, dnskey_record = get_validate_dnssec_support( \
            search_domain, servers, hash_algo, ds_record)
        if ind == len(servers):
            return None            
        
        search_domain = current_domain + '.' + search_domain

        for ind in range(0, len(servers)):
            if next_level_servers:
                servers = next_level_servers
                break
            (next_level_servers, ds_record, hash_algo) = get_parent_zone_details(search_domain, servers[ind])
            if ind == len(servers):
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

# As explained here tcp was used
# https://serverfault.com/questions/404840/when-do-dns-queries-use-tcp-instead-of-udp
def main(domain, category):
    
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

if __name__ == '__main__':
    category = 'A' 
    domain = sys.argv[1]
    if (len(sys.argv) > 2):
        category = sys.argv[2]
    main(domain, category)


