# Copyright 2014 - Sean Donovan
# This defines rules for NetAssay.


    



class AssayRule:
    # Ruletypes!
    CLASSIFICATION = 1
    AS             = 2
    DNS_NAME       = 3
    classtypes = [CLASSIFICATION, AS, DNS_NAME]

    def __init__(self, ruletype, value, rule_update_cbs=[]):
        self.type = ruletype
        self.value = value
        self.update_callbacks = rule_update_cbs

        #Rules should be proper pyretic rules
        #The _rule_list is composed in parallel to get the _ruleset
        #This allows for FAR easier manipulation of the rules that are active.
        self._ruleset = None
        self._rule_list = []  


    def set_update_callback(self, cb):
        #these callbacks take an AssayRule as input
        self.update_callbacks.append(cb)

    def add_rule(self, newrule):
        # Does not check to see if it's a duplicate rule, as this allows the 
        # same rule to be installed for different reasons, and they can be 
        # removed individually.
        self._rule_list.append(newrule)
        self._update_ruleset()
        
    def has_rule(self, newrule):
        return newrule in self._rule_list

    def remove_rule(self, newrule):
        self._rule_list.remove(newrule)
        self._update_ruleset()                

    def _update_ruleset(self):
        new_ruleset = None
        for rule in self._rule_list:
            if new_ruleset == None:
                new_ruleset = rule
            else:
                new_ruleset = new_ruleset + rule
        self._ruleset = new_ruleset
        for cb in self.update_callbacks:
            cb(self)

    def get_ruleset(self):
        return self._ruleset

    def get_list_of_rules(self):
        return self._rulelist
