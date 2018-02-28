import time
import socket
import dns.resolver
import numpy as np
import matplotlib.pyplot as plt
import my_resolver


alexa_sites = ['Google.com',
               'Youtube.com',
               'Facebook.com',
               'Baidu.com',
               'Wikipedia.org',
               'Reddit.com',
               'Yahoo.com',
               'Google.co.in',
               'Qq.com',
               'Taobao.com',
               'Amazon.com',
               'Tmall.com',
               'Twitter.com',
               'Google.co.jp',
               'Instagram.com',
               'Live.com',
               'Sohu.com',
               'Vk.com',
               'Sina.com.cn',
               'Jd.com',
               'Weibo.com',
               '360.cn',
               'Google.de',
               'Google.co.uk',
               'Google.com.br'
        ]

# http://apprize.info/python/network/6.html
# https://stackoverflow.com/questions/3898363/set-specific-dns-server-using-dns-resolver-pythondns
if __name__ == "__main__":
    
    # Experiment 1 - Run your DNS resolver on each website 10  times, and find the average 
    # time to resolve the DNS for each of the 25 website.
    
    result_my_resolver = []
    result_local_dns = [] # 207.244.82.25, 108.59.15.5
    result_google_dns = []

    google_resolver = dns.resolver.Resolver()
    google_resolver.nameservers = ['8.8.8.8']
    
    for website in alexa_sites:
        print("Running for : " + str(website))
        curr_my_resolver_time = 0
        curr_local_dns_time = 0
        curr_google_dns_time = 0
        for ind in range(0, 10):
            
            start = time.time()
            my_resolver.main(website, 'A')
            curr_my_resolver_time += (time.time() - start)

            start = time.time()
            socket.gethostbyname(website)
            curr_local_dns_time += (time.time() - start)

            start = time.time()
            google_resolver.query(website)
            curr_google_dns_time += (time.time() - start)
            

        result_my_resolver.append(100.0 * curr_my_resolver_time)
        result_local_dns.append(100.0 * curr_local_dns_time)
        result_google_dns.append(100.0 * curr_google_dns_time)

    print("*****************************************")
    print("My resolver - " + str(result_my_resolver))
    print("*****************************************")
    print("Local DNS - " + str(result_local_dns))
    print("*****************************************")
    print("Google DNS - " + str(result_google_dns))
    print("*****************************************")        

    X, A = np.histogram(result_my_resolver, bins=1000)
    Y, B = np.histogram(result_local_dns, bins=1000)
    Z, C = np.histogram(result_google_dns, bins=1000)

    CUM_X = np.cumsum(X)
    CUM_Y = np.cumsum(Y)
    CUM_Z = np.cumsum(Z)

    plt.xlabel("Time (millisec)")
    plt.ylabel("Cumulative DistributionFrequency")

    plt.plot(A[:-1], CUM_X, c='red', label='My Resolver')
    plt.plot(B[:-1], CUM_Y, c='blue', label='Local Resolver')
    plt.plot(C[:-1], CUM_Z, c='green', label='Google Resolver')
    plt.legend(loc="best")

    plt.savefig("result.png")
    plt.show()

    input("Enter to close")
    


