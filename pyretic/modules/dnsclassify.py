# Copyright 2014 -  Sean Donovan
# Based off of https://github.com/shahifaqeer/dnsclassifier. Modified
# to work with Pyretic.

from collections import defaultdict
from ryu.lib.packet.dns import *
from mapper import Mapper
from datetime import datetime, timedelta

# need hooks for passing in DNS packets
#    Parsing out different types
#    adding to database function - helper
# need callback functions (?)
#    Expiry of known DNS entry
# need to convert TTLs to end-of-life timeouts
# printing out of current database
# querying by IP (string)
# prepopulating db from a file?

# Database dictionary of dictionaries:
#    Primary key - IP address string - returns the dictionary associated with IP
#    Secondary keys
#        record types?
#        'ttl' - TTL value from the packet
#        'expiry' - actual time off of expiration - 
#                   upon hitting, delete/move to "expired" list
#        'classification'
#

class DNSClassifierException(Exception):
    pass

class DNSClassifier:
    def __init__(self):
        #may want to enhance this with a pre-load file to prepopulate the DB
        self.db = {}
        self.mapper = Mapper()
        self.new_callbacks = []        # For each new entry
        self.updated_callbacks = []    # For each time an entry is updated
        self.all_callbacks = []        # When entry is updated or new



    def _full_query(self, ipaddr):
        """Returns the entire database entry of a particular ipaddr"""
        return self.db[ipaddr]
    
    def _query_by_name(self, name):
        """Returns a dictionary of database entries for a particular webname
           Dictionary will be ipaddr:dbentry
        """
        retdict = {}
        for key in self.db.keys():
            for nameval in self.db[key]['name']:
                if nameval == name:
                    retdict[key] = self.db[key]
                    continue # don't need to look at any more of the names
        return retdict

    def _from_classification(self, classification):
        """Returns a dictionary of database entries from a particular category
           Dictionary will be ipaddr:dbentry
        """
        retdict = {}
        for key in self.db.keys():
            if classification == self.db[key]['classification']:
                retdict[key] = self.db[key]
        return retdict


    def query(self, ipaddr):
        """Returns the classification of a particular ipaddr"""
        entry = _full_query(ipaddr)
        if entry != None:
            return entry['classification']
        return None

    
    def has(self, ipaddr):
        """Returns true if we have a record for a particular IP address.
           Returns fase if we don't have an active record for a particular
           IP address.
        """
        if ipaddr not in self.db.keys():
            return false        
        return _check_expiry(ipaddr)

    def parse_new_DNS(self, packet):
        # Only look at responses with 'No error' reply code
        dns_parsed = dns.parser(packet)
        if (dns_parsed.qr and dns_parsed.rcode == 0000):
            # skip the questions...
            # we don't care about authorities
            # we care about answers
            # we care about additional - could be some goodies in there
            for resp in (dns_parsed.answers + dns_parsed.additional):
                # save off the ttl, classification, calculate expiry time
                # Name of item that's being saved, 
                if (resp.qtype == dns.rr.A_TYPE):
                    expiry = datetime.now() + timedelta(seconds=resp.ttl)
                    classification = self.mapper.searchType(resp.name)
                    addr = addrconv.ipv4.bin_to_text(resp.rddata)
                    
                    if addr not in self.db.keys():
                        self.db[addr] =  {
                            'name' : list(),
                            'ttl' : resp.ttl,
                            'classification' : classification,                     
                            'expiry' : expiry}
                        self.db[addr]['name'].append(resp.name)
                        for callback in self.new_callbacks:
                            callback(addr, self.db[addr])
                    else:

                        self.db[addr]['ttl'] = resp.ttl
                        self.db[addr]['classification'] = classification
                        self.db[addr]['expiry'] = expiry
                        if resp.name not in self.db[addr]['name']:
                            self.db[addr]['name'].append(resp.name)
                        for callback in self.updated_callbacks:
                            callback(addr, self.db[addr])
                    for callback in self.all_callbacks:
                        callback(addr, self.db[addr])
                    

                elif (resp.qtype == dns.rr.AAAA_TYPE):
                    #placeholder
                    print "Found a AAAA"
                elif (resp.qtype == dns.rr.CNAME_TYPE):
                    #placeholder
                    print "Found a CNAME!"
                elif (resp.qtype == dns.rr.MX_TYPE):
                    #placeholder
                    print "Found an MX!"

    def _check_expiry(self, ipaddr):
        # checks individual entries to see if they're expired
        now = datetime.now()
        if entry['expiry'] < now:
            #expired
            return True
        return False

    def _clean_expiry_full(self):
        # Loop through everything to check for expired DNS entries
        now = datetime.now()
        for key in self.db.keys():
            entry = self.db[key]
            if entry['ttl'] < now:
                del db[key]

    def clean_expired(self):
        self._clean_expiry_full()
        
    def print_entries(self):
        for key in self.db.keys():
            entry = self.db[key]
            print key
            names = ''
            for name in entry['name']:
                names = names + name + " "
            print "   " + names
            print "   " + str(entry['ttl'])
            print "   " + entry['classification']
            print "   " + str(entry['expiry'])
            print "   Expired? " + str(self._check_expiry(key))

    def print_entry(self, entry, offset="   "):
        names = ''
        for name in entry['name']:
            names = names + name + " "
        print offset + names
        print offset + str(entry['ttl'])
        print offset + entry['classification']
        print offset + str(entry['expiry'])
#        print offset + "Expired? " + str(self._check_expiry(key))


    def set_new_callback(self, cb):
        self.new_callbacks.append(cb)

    def set_updated_callback(self, cb):
        self.updated_callbacks.append(cb)

    def set_all_callback(self, cb):
        self.all_callbacks.append(cb)

    def set_per_ip_callback(
