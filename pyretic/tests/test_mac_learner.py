#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController
import os, utils, time
from utils import init


### Module Parameters

def get_controller():
    return 'pyretic.modules.mac_learner'

def run_mininet():
    mn = Mininet()
    s1 = mn.addSwitch('s1')
    s2 = mn.addSwitch('s2')
    s3 = mn.addSwitch('s3')
    h1 = mn.addHost('h1')
    h2 = mn.addHost('h2')
    h3 = mn.addHost('h3')
    mn.addLink(s1, s2)
    mn.addLink(s1, s3)
    mn.addLink(s2, s3)
    mn.addLink(h1, s1)
    mn.addLink(h2, s2)
    mn.addLink(h3, s3)
    mn.addController('c0', RemoteController)
    time.sleep(1)
    mn.run(mn.pingAll)

    # Alternately, run mininet via the command line.  Note that we need to use
    # absolute path names because sudo mucks with the env.

    # mn = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../mininet.sh'))
    # cmd = '%s --topo clique,4,4' % mn
    # subprocess.call(shlex.split(cmd))

def filter_mininet(line):
    return line

def filter_controller(line):
    if line.find('TEST') >= 0:
        return line
    else:
        return ''


### Tests

test_mac_learner = utils.TestModule( __name__, __file__, get_controller, run_mininet, filter_controller, filter_mininet)

def test_mac_learner_i(init):
    utils.run_test(test_mac_learner, init.test_dir, init.benchmark_dir, '-m i')
def test_mac_learner_r0(init):
    utils.run_test(test_mac_learner, init.test_dir, init.benchmark_dir, '-m r0')
# def test_mac_learner_p0(init):
#     utils.run_test(test_mac_learner, init.test_dir, init.benchmark_dir, '-m p0')
# def test_mac_learner_p1(init):
#     utils.run_test(test_mac_learner, init.test_dir, init.benchmark_dir, '-m p1')

if __name__ == "__main__":
    run_mininet()