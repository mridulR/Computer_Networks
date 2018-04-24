import socket
from threading import Lock, Thread
import time
import sys
import os
import json
import io

## Global variables for all threads - clients and server.

## As given, we assume every node knows about the topology i.e every other node.
hosts = ['H1', 'H2', 'R1', 'R2', 'R3', 'R4']
neighbouring_nodes = {}
distance_vector = {}   ###   This is critical section. Update it using locks. <rechable_node>, (<cost, next_hop>)
lock = Lock()
current_time = 0

'''
Print distance vector in the form <Reachable Node> <Cost> <Next Hop>
'''
def print_distance_vector(host_name):

    print '\n'
    print 'Dest \t Cost \t NextHop \t ==>  %s distance vector\n' % host_name
    for reach_node in distance_vector.keys():
        cost = distance_vector[reach_node][0]
        if cost == (sys.maxint):
            cost = 'infinity'
        else:
            cost = str(cost)
        print '%s \t %s \t %s \n' % (reach_node, cost, distance_vector[reach_node][1])
    millis = int(round(time.time() * 1000)) - current_time
    print 'time taken - %s'  %(millis)    
    print '\n'

'''
If changes are either received from neighbours or file updated, then notify all neighbours
'''
def update_neighbours(host_distance_vector):
    for host in neighbouring_nodes.keys():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', int(neighbouring_nodes[host])))
            s.sendall(host_distance_vector.encode('utf8'))
        except Exception as ex:
            print ex

'''
This is bellmond ford algorithm. Updating of distance vector by different
neighbours should be serialized. Hence, using locks.
'''
def update_distance_vector_bf(host_name, sender_distance_vector, sender):
    lock.acquire()
    propagate_change = False

    for key in sender_distance_vector.keys():
        old_distance = distance_vector[key][0]
        new_distance = distance_vector[sender][0] + sender_distance_vector[key][0]
        ## print 'newdistance %s and olddistance %s', %(new_distance, old_distance)
        if old_distance > new_distance:
            distance_vector[key] = (new_distance, sender)
            propagate_change = True
    ## print 'propagate - %s' , %(propagate_change) 
    if propagate_change is True:
        update_neighbours(json.dumps((distance_vector, host_name)))
        print_distance_vector(host_name)
    lock.release()


'''
Start client to pass message through TCP connections and run BellManFord algorithm
'''
def start_clients(server, monitor, host_name):
    try:
        while True:
            (client, address) = server.accept()
            data_received = client.recv(4096).decode('utf8')
            try:
                (data_rcv, sender) = json.loads(data_received)
                update_distance_vector_bf(host_name, data_rcv, sender)
                client.close()
            except ValueError:
                print 'Json decoding has failed'
    except Exception as ex:
        print ex
        server.close()
        monitor.join()

'''
All changes from file should be included. So no need to validate cost.
'''
def update_dv_from_file(host_name, weights):
    lock.acquire()

    changed = False
    
    for key in distance_vector.keys():
        (cost, next_hop) = distance_vector[key]
        if next_hop in weights.keys():
            distance_vector[key] = (weights[next_hop], next_hop)
            changed = True

    if changed is True:
        update_neighbours(json.dumps((distance_vector, host_name)))
    
    lock.release()

'''
open file and read bi-directional weights
'''
def get_weights(filename, host_name):
    weights = {}
    with io.open(filename, encoding='utf-8') as f:
        for line in f:
            node_node_cost = line.split(',')
            if node_node_cost[0] == host_name:
                weights[node_node_cost[1]] = int(node_node_cost[2])
            elif node_node_cost[1] == host_name:
                weights[node_node_cost[0]] = int(node_node_cost[2])
    return weights


'''
Repeatedly check topology file to be modified.
'''
def repeat_read_topology_file(host_name):

    time.sleep(5)
    filename = 'links_weight.txt'
    prev_updated = -1

    recent_updated = os.stat(filename).st_mtime
    if prev_updated < recent_updated:
        prev_updated = recent_updated
        weights = get_weights(filename, host_name)
        update_dv_from_file(host_name, weights)


'''
Start thread for monitoring distance-vector change.
'''
def start_monitoring_topology_file(host_name):
    monitor = Thread(target=repeat_read_topology_file, args=(host_name,))
    monitor.start()
    return monitor

'''
Server will start at localhost and bind at the port provided.
'''
def start_server(host_name, host_port):
    print 'Server Name  - %s and Server Port - %s \n' % (host_name, host_port)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', host_port))
    server.listen(5)
    return server

'''
Cost to same node is 0 and any other node is sys.maxint
'''
def initialize_distance_vector(host_name):
    global distance_vector
    for host in hosts:
        if host == host_name:
            distance_vector[host] = (0, host)
        else:
            distance_vector[host] = (sys.maxint, host)
        ## print 'host - %s , cost - %s, next hop - %s' , %(host, distance_vector[host][0], distance_vector[host][1])

'''
   This is the starting of RIP-Lite protocol code.
   Arguments passed to this script are <host_name>, <port_no> <json string of immediate neighbours with their port>
   This script should be invoked for every host. First of all file is topology file is read and cost and route data
   is shared among the immediate neighbours. Bellmond-Ford algorithm is run at every host to figure out the distance-
   vector. Any update in the file is shared by the neighbours and protocol reruns to calculate distance-vector.
'''
if __name__ == '__main__':

    ## Initialize parameters
    host_name = sys.argv[1]
    host_port = int(sys.argv[2])

    neighbouring_nodes = {}
    try:
        neighbouring_nodes = json.loads(sys.argv[3])
    except ValueError:
        print 'Json decoding has failed'
        exit(0)
    
    print 'Neighbours :'
    print json.dumps(neighbouring_nodes, indent=4, sort_keys=True)
    print '\n'
    
    initialize_distance_vector(host_name)

    # print 'Initial Distance vector :'
    # print json.dumps(distance_vector, indent=4, sort_keys=True)
    # print '\n'

    server = start_server(host_name, host_port)

    time.sleep(15) ## For binding every server to port before clients start updating distance vector
    current_time =  int(round(time.time() * 1000))
    
    monitor = start_monitoring_topology_file(host_name)
    
    start_clients(server, monitor, host_name)

