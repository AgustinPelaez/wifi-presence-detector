from multiprocessing import Process, Manager
from scapy.all import *
import ubidots
import csv
import time

# Declare variables

users = {}
office = "Boston"
MAX_RETRIES = 25
SUB_NET = "192.168.0.0/24"

# Functions

def check_incoming_users(users_ip):
    while(True):
        sniff(prn = arp_count, filter = "arp", count = 10)


def check_outgoing_users(users_ip):
    conf.verb = 0
    timeout_counters = {}
    while(True):
        # Issue ARP Ping to all network
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=SUB_NET),timeout=2)
        for user,ip in users_ip.items():
            for snd,rcv in ans:
                if ip == rcv.sprintf("%ARP.psrc%"):
                    print "ARP ping reply from " + user
                    timeout_counters[user] = 0
                    try:
                        var = get_var_by_name(user, ds)
                        var.save_value({"value": 1,"context":{"type":"ARP Ping"}})
                        break
                    except:
                        break
            else:
                print user + " not replying to ARP ping."
                timeout_counters[user] = timeout_counters.get(user, 0) + 1
                if timeout_counters[user] > MAX_RETRIES:
                    print "Reporting user as gone..."
                    timeout_counters[user] = 0
                    try:
                        var = get_var_by_name(user, ds)
                        var.save_value({"value": 0})
                    except:
                        continue

def arp_count(pkt):

    try:
        if pkt[ARP].hwsrc in users:
            device = users[pkt[ARP].hwsrc]
            users_ip[device] = pkt[ARP].psrc
            print "ARP request received from " + device
            var = get_var_by_name(device, ds)
            var.save_value({"value": 1,"context":{"type":"ARP Request"}})
            return
        else:
            #print "Scapy running - HW address not found"
            return
    except:
        return

def get_var_by_name(var_name, ds):

    # Search for a variable in a datasource. If found, returns the variable. If not found, returns None
    try:
        for var in ds.get_variables():

            if var.name == var_name:
                return var

        var = ds.create_variable({"name": var_name, "unit": "."})
        return var
    except:
        print "Couldn't get variables from DS"
        return

if __name__ == '__main__':

    # Create Ubidots connection

    api = ubidots.ApiClient("YOUR-UBIDOTS-API-KEY")

    # Search for a data source with name matching this. If it doesn't exist, create it.

    ds = None

    try:
        for cur_ds in api.get_datasources():
            if cur_ds.name == office:
                ds = cur_ds
                break

            if ds is None:
                ds = api.create_datasource({"name": office})
        print "Connected to Ubidots, will send data to Ubidots data source called: " + ds.name

    except:
        print "Ds not found nor created"

    # Load dictionary from CSV file

    with open('/root/dictionary.csv','rb') as f:
        reader = csv.reader(f)
        for row in reader:
            users[row[1]] = row[0]
            var = get_var_by_name(row[0], ds)
            var.save_value({"value": 0})

    print "List of users loaded."

    # Launch Processes
    manager = Manager()
    users_ip = manager.dict()

    p = Process(target=check_incoming_users, args=(users_ip,))
    p.start()

    check_outgoing_users(users_ip)
