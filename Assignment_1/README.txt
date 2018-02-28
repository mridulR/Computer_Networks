
Name - Mridul Ranjan
SBU Id - 111482003
Course - CSE 534 (Fundamentals Of Computer Networks)
Semester - Spring 2018
Assignment - HW1

Implementing Language - Python3
External Libraries used - dnspython

****************************
Instructions to run program:
****************************

Part A : Run DNS resolver - mydig (50 marks)

	1.) Relevant files :
		
			a.)  my_resolver.py - This is the recursive iterator written in python3 using dnspython library for 	                  resolving single iterative dns query. Ip addresses of root servers are hard-coded
								  in this file. This python script takes two arguments as input - domain and record type. 'A', 'NS' and 'MX' record types are supported.

			b.)  mydig - This is a wrapper script used to invoke my_resolver.py. This also accepts two arguments - 				domain and record type as input.

			c.)  mydig_output.txt - This file contains the output by running mydig program for all three types - 						 'A', 'NS' and 'MX'. 

	2.) Command to Execute :
			a.) Give executable permission to mydig script. Eg chmod 777 mydig
			b.) ./mydig www.cnn.com A

	3.) Sample input/output:

		Command : ./mydig www.cnn.com A
		Output:

				QUESTION SECTION:
				www.cnn.com. IN A

				ANSWER SECTION:
				www.cnn.com. 300 IN CNAME turner-tls.map.fastly.net.
				turner-tls.map.fastly.net. 30 IN A 151.101.201.67

				Query Time: 398 msec
				WHEN: Mon Feb 19 13:00:27 2018
				MSG SIZE rcvd : 504 

	4.) Handling corner cases :
				
				In some	cases, you	may	need additional	resolution.	For	example, google.co.jp will often not	resolve	to	an	IP	address	in	one	pass. why the resolution did not complete in one pass in	this corner	case.

				Explanation : This happens because dns resolution results in authoritative dns name servers in authority section rather than resolving to ip. So first we need to resolve this NS record and from that name server we need to query for the given domain. This case was handled in the tool by checking the answer section to be non-empty and if it contains CNAME or NS records then first resolve those types to get the desired 'A', 'NS' or 'MX' records. 




