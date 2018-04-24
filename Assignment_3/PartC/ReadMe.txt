
C1 :

RIP-lite: This is the application layer protocol that implements distance
vector routing useing Bellman-Ford algorithm.

Rip_lite code is attached in the submission.

Time taken for the protocol to find the shortest path is 19.988 Seconds.

This was captured as follows.

For every node start-time was initialized.
Everytime the protocol made chages to the distance vector, total time so far was calculated.
Finally in the end when the protocol converges, we get the running time.

Application layer routing table are attched.

C2 :

  When link R1-R3 was changed from 6 to 1
  It took approximately 20 more seconds for the protocol to converge.

  It was inferred from the logs.
  All modified distance vectors are included in the submission.

C3 :

  If the edge has negative weight, we need to handle them appropriately.
  If there are n edges we need to iterate (n-1) times and then break from 
  the loop stating that the graph has negative cycle.

  Also, before updating we can check for the value to be negative.

How to run ?

Open 6 terminal:
 1.) python rip_lite.py H1 9001 '{"R1" : "9002"}'
 2.) python rip_lite.py R1 9002 '{"H1" : "9001", "R2" : "9003", "R3" : "9004"}'
 3.) python rip_lite.py R2 9003 '{"R1" : "9002", "R4" : "9005"}'
 4.) python rip_lite.py R3 9004 '{"R1" : "9002", "R4" : "9005"}' 
 5.) python rip_lite.py R4 9005 '{"R2" : "9003", "R3" : "9004", "H2" : "9006"}'
 6.) python rip_lite.py H2 9006 '{"R4" : "9005"}'

 Distance vectors with time taken will be printed on console.

