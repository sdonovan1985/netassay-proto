# Copyright 2014 - Sean Donovan

import logging

from pyretic.core.language import Filter
from pyretic.modules.assayrule import *
from pyretic.modules.dnsme import *
from pyretic.modules.bgpme import *

class MainControlModuleException(Exception):
    pass

# All the new matchXXXX policies should inherit from here. They are all very
# similar, so there is tremendous reuse of code. 
# This is based on match from pyretic.core.langauge
class NetAssayMatch(Filter):
    def __init__(self, metadata_engine, ruletype, rulevalue):
        loggername = "netassay." + self.__class__.__name__
        logging.getLogger(loggername).info("__init__(): called")
        self.logger = logging.getLogger(loggername)
        # probably should verify that the URL is vaid...
        self.me = metadata_engine 
        self.assayrule = AssayRule(ruletype, rulevalue)
        self.assayrule.set_update_callback(AssayMainControlModule.get_instance().rule_update)
        self.me.new_rule(self.assayrule)
        self._classifier = self.generate_classifier()

        #FIXME
        self.map = {}

    def eval(self, pkt):
        for rule in self.assayrule.get_list_of_rules():
            if rule.eval(pkt) == pkt:
                return pkt
        return set()

    def __repr__(self):
        retval = self.__class__.__name__ + ": " + self.assayrule.value
        for rule in self.assayrule.get_list_of_rules():
            retval = retval + "\n   " + str(rule)
        return retval

    def generate_classifier(self):
        #lovingly stolen from class match.
        r1 = Rule(self,[identity])
        r2 = Rule(identity,[drop])
        return Classifier([r1, r2])

    def __eq__(self, other):
        return (isinstance(other, type(self)) and 
                self.assayrule.type == other.assayrule.type and
                self.assayrule.value == other.assayrule.value)

    def intersect(self, pol):
        self.logger.debug("Intersect called")

        current_min = identity
        if isinstance(pol, NetAssayMatch):
            for rule in pol.assayrule.get_list_of_rules():
                if current_min == None:
                    current_min = rule
                    continue
                current_min = rule.intersect(current_min)
        else:
            current_min = pol

        for rule in self.assayrule.get_list_of_rules():
            current_min = rule.intersect(current_min)
        self.logger.debug("current_min = " + str(current_min))
        return current_min

    def __and__(self, pol):
        raise MainControlModuleException(self.__class__.__name__+":__and__")

    def __hash__(self, pol):
        raise MainControlModuleException(self.__class__.__name__+":__hash__")

    def covers(self, other):
        if (other == self):
            return True
        return False




class matchAS(NetAssayMatch):
    """
    matches IP prefixes related to the specified AS.
    """
    def __init__(self, asnum):
        logging.getLogger('netassay.matchAS').info("matchAS.__init__(): called")
        metadata_engine = BGPMetadataEngine.get_instance()
        ruletype = AssayRule.AS
        rulevalue = asnum
        super(matchAS, self).__init__(metadata_engine, ruletype, rulevalue)

class matchASPath(NetAssayMatch):
    """
    matches IP prefixes related to the specified AS.
    """
    def __init__(self, asnum):
        logging.getLogger('netassay.matchASPath').info("matchASPath.__init__(): called")
        metadata_engine = BGPMetadataEngine.get_instance()
        ruletype = AssayRule.AS_IN_PATH
        rulevalue = asnum
        super(matchASPath, self).__init__(metadata_engine, ruletype, rulevalue)

class matchURL(NetAssayMatch):
    """
    matches IPs related to the specified URL.
    """
    def __init__(self, url):
        logging.getLogger('netassay.matchURL').info("matchURL.__init__(): called")
        metadata_engine = DNSMetadataEngine.get_instance()
        ruletype = AssayRule.DNS_NAME
        rulevalue = url
        super(matchURL, self).__init__(metadata_engine, ruletype, rulevalue)

class matchClass(NetAssayMatch):
    """
    matches IPs related to the specified class of URLs.
    """
    def __init__(self, classification):
        logging.getLogger('netassay.matchClass').info("matchURL.__init__(): called")
        metadata_engine = DNSMetadataEngine.get_instance()
        ruletype = AssayRule.CLASSIFICATION
        rulevalue = classification
        super(matchClass, self).__init__(metadata_engine, ruletype, rulevalue)


#--------------------------------------
# MAIN CONTROL MODULE - MCM
#--------------------------------------
class AssayMainControlModule:
    INSTANCE = None
    # Singleton! should be initialized once by the overall control program!

    def __init__(self):
        if self.INSTANCE is not None:
            raise ValueError("Instance already exists!")

        #Basic setup
        self.setup_logger()

        self.logger.info("AssayMCM.__init__(): called") 

        #DME setup
        self.dnsme = DNSMetadataEngine.get_instance() 
        self.dnsme_rules = self.dnsme.get_forwarding_rules()

        #BME setup
        self.bgpme = BGPMetadataEngine.get_instance()
        self.bgpme_rules = self.bgpme.get_forwarding_rules() #Doesn't have any...

        #General information
        self.update_policy_cb = None

        self.logger.info("AssayMainControlModule Initialized!")


    @classmethod
    def get_instance(cls):
        if cls.INSTANCE is None:
            cls.INSTANCE = AssayMainControlModule()
        return cls.INSTANCE

    def setup_logger(self):
        formatter = logging.Formatter('%(asctime)s %(name)-12s: %(levelname)-8s %(message)s')
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(formatter)
        logfile = logging.FileHandler('netassay.log')
        logfile.setLevel(logging.DEBUG)
        logfile.setFormatter(formatter)
        self.logger = logging.getLogger('netassay')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(console)
        self.logger.addHandler(logfile)


    def set_update_policy_callback(self, cb):
        self.logger.info("AssayMCM:set_update_policy_callback(): called")
        self.logger.debug("    callback: " + str(cb))
        self.update_policy_cb = cb

    def rule_update(self, assayrule):
        #This is called whenever an AssayRule gets a ruleupdate
        self.logger.info("AssayMCM:rule_update(): called")
        if self.update_policy_cb is not None:
            self.update_policy_cb()

    def get_assay_ruleset(self):
        """
        This should be called by the update_policy() routine to get any rules 
        that are specific to the MCM and it's children.
        In particular, this adds rules to redirect DNS response packets to the
        """
        self.logger.info("AssayMCM:get_assay_ruleset(): called")
        # Just keep adding on further rulesets as needed
        return self.dnsme_rules
