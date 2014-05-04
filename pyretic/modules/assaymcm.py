# Copyright 2014 - Sean Donovan

from pyretic.core.language import Filter
from pyretic.modules.assayrule import *
from pyretic.modules.dnsme import *

#this is based on match from pyretic.core.langauge
class matchAS(Filter):
    """
    matches only on IP addresses from the specified AS.
    """
    def __init__(self, AS):
        self.assayrule = AssayRule(AssayRule.AS, AS)
        self.assayrule.set_update_callback(AssayMainControlModule.get_instance().rule_update)
        pass

    def eval(self, pkt):
        pass

    def __or__(self, pol):
        pass

    def __and__(self, pol):
        pass

    def __repr__(self):
        return "matchAS: %s" % ' '.join(map(str,self.map.items()))

#this is based on match from pyretic.core.langauge
class matchClass(Filter):
    """
    matches only on IP addresses from the specified AS.
    """
    def __init__(self, classification):
        # probably should verify that the class is vaid...
        self.dme = DNSMetadataEngine.get_instance()
        self.assayrule = AssayRule(AssayRule.CLASSIFICATION, classification)
        self.assayrule.set_update_callback(AssayMainControlModule.get_instance().rule_update)
        self.dme.new_rule(self.assayrule)


    def eval(self, pkt):
        for rule in self.assayrule.get_list_of_rules():
            if rule.eval(pkt) == pkt:
                return pkt
        return set()

    def __repr__(self):
        return "matchClass: " + self.assayrule.value

#this is based on match from pyretic.core.langauge
class matchURL(Filter):
    """
    matches only on IP addresses from the specified url.
    """
    def __init__(self, url):
        # probably should verify that the URL is vaid...
        self.dme = DNSMetadataEngine.get_instance()
        self.assayrule = AssayRule(AssayRule.DNS_NAME, url)
        self.assayrule.set_update_callback(AssayMainControlModule.get_instance().rule_update)
        self.dme.new_rule(self.assayrule)
    
    def eval(self, pkt):
        for rule in self.assayrule.get_list_of_rules():
            if rule.eval(pkt) == pkt:
                return pkt
        return set()

    def __repr__(self):
        return "matchURL: " + self.assayrule.value


class AssayMainControlModule:
    INSTANCE = None
    # Singleton! should be initialized once by the overall control program!

    def __init__(self):
        if self.INSTANCE is not None:
            raise ValueError("Instance already exists!")
        
        #DME setup
        print "about to call DNSME"
        self.dnsme = DNSMetadataEngine.get_instance() 
        print "Finished call DNSME"
        self.dnsme_rules = self.dnsme.get_forwarding_rules()

        #BGP setup

        #General information
        self.update_policy_cb = None

        print "AssayMainControlModule Initialized!"


    @classmethod
    def get_instance(cls):
        if cls.INSTANCE is None:
            cls.INSTANCE = AssayMainControlModule()
        return cls.INSTANCE

    def set_update_policy_callback(self, cb):
        self.update_policy_cb = cb

    def rule_update(self, assayrule):
        #This is called whenever an AssayRule gets a ruleupdate
        if self.update_policy_cb is not None:
            self.update_policy_cb()

    def get_assay_ruleset(self):
        """
        This should be called by the update_policy() routine to get any rules 
        that are specific to the MCM and it's children.
        In particular, this adds rules to redirect DNS response packets to the
        """

        # Just keep adding on further rulesets
        return self.dnsme_rules
