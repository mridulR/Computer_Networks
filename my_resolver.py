import sys
import time
import dns
import dns.inet
import dns.name
import dns.query
import dns.message
import dns.resolver
import dns.rdataclass
import dns.rdatatype

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

# If the server is available, return sub-domains.
# In case of exception, return None so that other servers can be tried.
# http://blog.catchpoint.com/2014/07/09/dissecting-dns-communications/
# http://www.zytrax.com/books/dns/ch15/
# http://www.dnspython.org/docs/1.15.0/dns.message.Message-class.html
def get_sub_domain_servers(domain, server, category):
    global message_size
    servers = []
    try:
        query = dns.message.make_query(domain, category)
        response = dns.query.udp(query, server, timeout=1)
        message_size += sys.getsizeof(response)

        #print("Response - : " + str(response))
        if response.rcode() != dns.rcode.NOERROR:
            return None

        # if answer is found, return
        if len(response.answer) > 0:
            servers.append(server)
            return servers

        # if SOA data type in authority, then also return
        if len(response.authority) > 0:
            rrset = response.authority[0]
            if rrset[0].rdtype == dns.rdatatype.SOA:
                servers.append(server)
                return servers
        # if no answer or SOA found resolve NS
        while len(servers) == 0:
            for auth_record in response.authority:
                authority = auth_record[0].target.to_text()
                if len(response.additional) > 0:
                    rrset = response.additional
                    for rr in rrset:
                        servers.append(rr[0].to_text())
                else:
                    servers = get_domain_servers(authority, category)
                if len(servers) != 0:
                    break
    except Exception:
        return None
    return servers

def get_tld_servers(tld_domain, category):
    tld_servers = None
    for root_server in root_servers:
        tld_servers = get_sub_domain_servers(tld_domain, root_server, category)
        if tld_servers:
            break;
    return tld_servers


# Staring from root dns, this method finally resolves dns level by level.
# Once we traverse one level, we do not need to recursively traverse other nodes
# at the same level as any server will list complete list of sub-domains in the next level.
def get_domain_servers(domain, category):
    domain = dns.name.from_text(domain)
    sub_domains = str(domain).split('.')
    sub_domains = list(reversed(sub_domains))
    search_domain = sub_domains[1] + '.'
    servers = get_tld_servers(search_domain, category)
    if servers:
        for ind in range(2, len(sub_domains)):
            if not servers:
                break;
            search_domain = sub_domains[ind] + '.' + search_domain
            sub_domain_servers = None
            for server in servers:
                try:
                    sub_domain_servers = get_sub_domain_servers(search_domain, server, category)
                    if sub_domain_servers:
                        servers = sub_domain_servers
                        break
                except:
                    # Retry with next server
                    pass
    else:
        return None
    return servers


# First get list of domain servers by first querying root server
# and then TLD and iteratively domain and sub-domain thereafter. Once domain server list is obtained
# iterate through it till you get response.
def resolve_domain_category(domain, category):
    global message_size
    query = dns.message.make_query(domain, category)
    response = None
    servers = get_domain_servers(domain, category)
    if servers:
        for server in servers:
            try:
                response = dns.query.udp(query, server, timeout=1)
                message_size += sys.getsizeof(response)
            except:
                ## Try with other servers
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

def main(domain, category):
   
    if domain and category:
        start_time = int(round(time.time() * 1000))
        global message_size
        message_size = 0
        result = resolve_domain_category(domain, category);
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
        print("Domain and Category shoudn't be empty for resolution.")

if __name__ == '__main__':
    category = 'A'
    domain = sys.argv[1]
    if len(sys.argv) > 2:
        category = sys.argv[2]
    main(domain, category)    
