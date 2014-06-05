# Copyright 2014 - Sean Donovan

import logging

from pyretic.core.language import Filter
from pyretic.modules.assayrule import *
from pyretic.modules.dnsme import *

class MainControlModuleException(Exception):
    pass

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
        logging.getLogger('netassay.matchClass').info("matchClass.__init__(): called")
        self.logger = logging.getLogger('netassay.matchClass')
        # probably should verify that the URL is vaid...
        self.dme = DNSMetadataEngine.get_instance()
        self.assayrule = AssayRule(AssayRule.CLASSIFICATION, classification)
        self.assayrule.set_update_callback(AssayMainControlModule.get_instance().rule_update)
        self.dme.new_rule(self.assayrule)
        self._classifier = self.generate_classifier()

        #FIXME
        self.map = {}


    def eval(self, pkt):
        for rule in self.assayrule.get_list_of_rules():
            if rule.eval(pkt) == pkt:
                return pkt
        return set()

    def __repr__(self):
        retval = "matchClass: " + self.assayrule.value
        for rule in self.assayrule.get_list_of_rules():
            retval = retval + "\n   " + str(rule)
        return retval
#"matchURL: " + self.assayrule.value

    def generate_classifier(self):
        #lovingly stolen from class match.
        r1 = Rule(self,[identity])
        r2 = Rule(identity,[drop])
        return Classifier([r1, r2])
#        raise MainControlModuleException("matchClass.generate_classifier")

    def __eq__(self, other):
        return (isinstance(other, matchClass) and 
                self.assayrule.type == other.assayrule.type and
                self.assayrule.value == other.assayrule.value)

    def intersect(self, pol):
        self.logger.debug("Intersect called")

        current_min = pol
        self.logger.debug("List length = " + str(len(self.assayrule.get_list_of_rules())))
        self.logger.debug("pol         = " + str(pol))

        for rule in self.assayrule.get_list_of_rules():
            current_min = rule.intersect(current_min)
        self.logger.debug("current_min = " + str(current_min))
        return current_min

    def __and__(self, pol):
        raise MainControlModuleException("matchClass.__and__")

    def __hash__(self, pol):
        raise MainControlModuleException("matchClass.__hash__")

    def covers(self, other):
        if (other == self):
            return True
        return False
        raise MainControlModuleException("matchClass.covers")


#this is based on match from pyretic.core.langauge
class matchURL(Filter):
    """
    matches only on IP addresses from the specified url.
    """
    def __init__(self, url):
        logging.getLogger('netassay.matchURL').info("matchURL.__init__(): called")
        self.logger = logging.getLogger('netassay.matchURL')
        # probably should verify that the URL is vaid...
        self.dme = DNSMetadataEngine.get_instance()
        self.assayrule = AssayRule(AssayRule.DNS_NAME, url)
        self.assayrule.set_update_callback(AssayMainControlModule.get_instance().rule_update)
        self.dme.new_rule(self.assayrule)
        self._classifier = self.generate_classifier()

        #FIXME
        self.map = {}


    
    def eval(self, pkt):
        for rule in self.assayrule.get_list_of_rules():
            if rule.eval(pkt) == pkt:
                return pkt
        return set()

    def __repr__(self):
        retval = "matchURL: " + self.assayrule.value
        for rule in self.assayrule.get_list_of_rules():
            retval = retval + "\n   " + str(rule)
        return retval
#"matchURL: " + self.assayrule.value

    def generate_classifier(self):
        #lovingly stolen from class match.
        r1 = Rule(self,[identity])
        r2 = Rule(identity,[drop])
        return Classifier([r1, r2])
#        raise MainControlModuleException("matchURL.generate_classifier")

    def __eq__(self, other):
        return (isinstance(other, matchURL) and 
                self.assayrule.type == other.assayrule.type and
                self.assayrule.value == other.assayrule.value)

    def intersect(self, pol):
        self.logger.debug("Intersect called")

        current_min = pol
        self.logger.debug("List length = " + str(len(self.assayrule.get_list_of_rules())))
        self.logger.debug("pol         = " + str(pol))

        for rule in self.assayrule.get_list_of_rules():
            current_min = rule.intersect(current_min)
        self.logger.debug("current_min = " + str(current_min))
        return current_min


#        return self.assayrule.get_ruleset().intersect(pol)
#        return pol.intersect(self.assayrule.get_ruleset())
#        if pol == identity:
#            return self
#        elif pol == drop:
#            return drop
#        elif not isinstance(pol, matchURL):
#            raise TypeError

        #TODO FIXME: this needs implementation
#        return self
        #raise MainControlModuleException("matchURL.intersect")

    def __and__(self, pol):
        raise MainControlModuleException("matchURL.__and__")

    def __hash__(self, pol):
        raise MainControlModuleException("matchURL.__hash__")

    def covers(self, other):
        if (other == self):
            return True
        return False
        raise MainControlModuleException("matchURL.covers")




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

        #BGP setup

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
        # Just keep adding on further rulesets
        return self.dnsme_rules
