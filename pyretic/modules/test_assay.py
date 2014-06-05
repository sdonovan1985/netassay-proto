from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.assaymcm import *


# There are 4 switches in the configuration: 
#                          +--+
#                      +---+s3+---+
#                    1 |   +--+   | 1 Slow Link
#             3  +--+--+          +----+--+   3
# Internet+------+s1|                  |s2+-------+h1
#                +--+--+          +----+--+
#                    2 |   +--+   | 2
#                      +---+s4+---+
#                          +--+
# Switch 3 and 4 behaviour is simple: in one port, out the other
# Switch 1 and 2 behaviour is a *touch* more complex. Anything coming from the 
# links to 3 or 4 goes to the Internet or host, respectively. Anything coming
# from the Internet or host can be manipulated - sent via the slow or fast
# paths, depending on what is needed.


class TestAssay(DynamicPolicy):
    def __init__(self):
        super(TestAssay, self).__init__()
        self.flood = flood()

        #Start up Assay and register update_policy()
        self.assay_mcm = AssayMainControlModule.get_instance()
        self.assay_mcm.set_update_policy_callback(self.update_policy)
        
        # set up s3 and s4's very basic rules
        
        self.s3rules = ((match(switch=3, inport=1) >> fwd(2)) + 
                        (match(switch=3, inport=2) >> fwd(1)))
        self.s4rules = ((match(switch=4, inport=1) >> fwd(2)) + 
                        (match(switch=4, inport=2) >> fwd(1)))

        #we care about source port first, then rest, use the if_ construct
        self.s1rules = ((match(switch=1, inport=1) >> fwd(3)) +
                        (match(switch=1, inport=2) >> fwd(3)) +
                        (match(switch=1, inport=3) >> fwd(1)))
        self.s2rules = ((match(switch=2, inport=1) >> fwd(3)) +
                        (match(switch=2, inport=2) >> fwd(3)) +
                        (match(switch=2, inport=3) >> fwd(1)))

        self.URLs1rules = ((match(switch=1, inport=1) >> fwd(3)) +
                           (match(switch=1, inport=2) >> fwd(3)) +
                           (match(switch=1, inport=3) >> 
                            if_(matchURL('google.com'), fwd(1), fwd(2))))
        self.URLs2rules = ((match(switch=2, inport=1) >> fwd(3)) +
                           (match(switch=2, inport=2) >> fwd(3)) +
                           (match(switch=2, inport=3) >>
                            if_(matchURL('google.com'), fwd(1), fwd(2))))
        self.CLASSs1rules = ((match(switch=1, inport=1) >> fwd(3)) +
                             (match(switch=1, inport=2) >> fwd(3)) +
                             (match(switch=1, inport=3) >> 
                              if_(matchClass('VIDEO'), fwd(1), fwd(2))))
        self.CLASSs2rules = ((match(switch=2, inport=1) >> fwd(3)) +
                             (match(switch=2, inport=2) >> fwd(3)) +
                             (match(switch=2, inport=3) >>
                              if_(matchClass('VIDEO'), fwd(1), fwd(2))))
        
        self.s1s2rules = ((match(switch=1) | match(switch=2)) >>
                          if_((match(inport=1)|match(inport=2)), fwd(3),
                              if_(matchURL('google.com'),fwd(1),fwd(2))))
#        self.s1s2rules = ((match(switch=2)
        self.update_policy()

    def update_policy(self):
        self.policy = self.s3rules + self.s4rules + self.assay_mcm.get_assay_ruleset()
#        self.policy = self.URLs1rules + self.URLs2rules + self.s3rules + self.s4rules + self.assay_mcm.get_assay_ruleset()
        self.policy = self.CLASSs1rules + self.CLASSs2rules + self.s3rules + self.s4rules + self.assay_mcm.get_assay_ruleset()
#        self.policy = self.s1rules + self.s2rules + self.s3rules + self.s4rules + self.assay_mcm.get_assay_ruleset()
# self.s1s2rules
        print self.policy


def main():
    return TestAssay()
    
