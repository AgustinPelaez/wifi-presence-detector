from multiprocessing import Process, Manager
from scapy.all import *
import ubidots
import csv
import time

# Declare variables

users = {}
office = "Acrecer Poblado"
MAX_RETRIES = 10

# Functions

def check_incoming_users(users_ip):
    """
    Main function to sniff ARP packets using Scapy
    """
    while(True):
        sniff(prn = arp_count, filter = "arp")
    
def arp_count(pkt):
    """
    This function is called everytime Scapy sniffs a packet. If the packet contains no ARP data, then it enters the exception and leaves.
    If it does contain ARP data, then it checks if the MAC address (pkt[ARP].hwsrc) is in the known devices list (dictionary.csv) and
    reports the user as online sending a "1" to the corresponding Ubidots variable.
    """
    try:
        if pkt[ARP].hwsrc in users:
            device = users[pkt[ARP].hwsrc]
            users_ip[device] = pkt[ARP].psrc
            print "ARP request received from " + device + ". Device saved to known hosts"
            var = get_var_by_name(device, ds)
            var.save_value({"value": 1,"context":{"type":"ARP Request"}})
            return
        else:
            #print "HW address not found"
            return
    except:
        return

def check_outgoing_users(users_ip):
    """
    Loops in the users_ip dict and sends an ICMP (ping) packet to each host, to check if it's still online.
    After MAX_RETRIES is reports the host as offline, sending a "0" to the corresponding Ubidots variable.
    """
    conf.verb = 0
    timeout_counters = {}
    while(True):
        for user,ip in users_ip.items():
            packet = IP(dst=ip, ttl=20)/ICMP()
            reply = sr1(packet, timeout=1)
            var = get_var_by_name(user, ds)
            if not (reply is None):
                print user + " is online!"
                timeout_counters[user] = 0
                var.save_value({"value": 1})
            else:
                print user + " is offline..."
                timeout_counters[user] = timeout_counters.get(user, 0) + 1
                if timeout_counters[user] > MAX_RETRIES:
                    print "Reporting user as gone..."
                    var.save_value({"value": 0})
                    del timeout_counters[user]
#                   del users_ip[user]    # Uncomment this line if you dont want to keep pinging the IP addresses that were reported offline
        time.sleep(1)

def get_var_by_name(var_name, ds):
    """
    Search for a variable in a datasource. If found, returns the variable. If not found, returns None
    """
    for var in ds.get_variables():

        if var.name == var_name:
            return var

    var = ds.create_variable({"name": var_name, "unit": "."})
    return var

if __name__ == '__main__':

    # Create Ubidots connection

    api = ubidots.ApiClient("YOU-UBIDOTS-API-KEY")

    # Search for a data source with name matching this. If it doesn't exist, create it.

    ds = None

    for cur_ds in api.get_datasources():
        if cur_ds.name == office:
            ds = cur_ds
            break

        if ds is None:
            ds = api.create_datasource({"name": office})

    # Load dictionary from CSV file

    with open('dictionary.csv','rb') as f:
        reader = csv.reader(f)
        for row in reader:
            users[row[1]] = row[0]
            var = get_var_by_name(row[0], ds)
            var.save_value({"value": 0})

    # Prepare and Launch Processes in Parallel
    
    manager = Manager()
    users_ip = manager.dict() 
    # This dict needs to be shared between both processes, so we use manager.dict() and pass it as an argument
    
    p1 = Process(target=check_incoming_users, args=(users_ip,))
    p2 = Process(target=check_outgoing_users, args=(users_ip,))

    p1.start()
    p2.start()

    p1.join()
    p2.join()
    
