import socket
import time
import datetime
from connpool_protocol import ProtocolError, Connection, ConnectionError
from config import load_config
import random
import logging

CONF = load_config()
network = "bitcoin"
network_data = CONF['networks'][network]
network_data['height'] = 706121

def get_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('')
    fileHandler = logging.FileHandler(log_file, mode='a+')
    fileHandler.setFormatter(formatter)
    l.setLevel(level)
    l.addHandler(fileHandler)
    return logging.getLogger(logger_name)

def bitnodes_code_ip(inp):
    if ".onion" in inp:
        address = inp[:inp.rfind(':')]
        port = inp[inp.rfind(':')+1:]
    elif "." in inp:
        address = inp[:inp.rfind(':')]
        port = inp[inp.rfind(':')+1:]
    elif "]" in inp:
        #IPv6
        address = inp[1:inp.rfind(':')-1]
        port = inp[inp.rfind(':')+1:]
    else:
        address = inp[:inp.rfind(':')]
        port = inp[inp.rfind(':')+1:]
    return address,port


def connect(network, address, port, to_services, network_data, user_agent=None, p2p_nodes=True,
            from_services=None, keepalive=False, attempt=1):
    now = datetime.datetime.utcnow()
    results = {'network': network, 'address': address, 'port': port, 'timestamp': now, 'seen': 0, 'attempt': attempt}
    offline = False
    handshake_fail = False
    breaked = False

    try:
        proxy = None
        if address.endswith(".onion"):
            proxy = CONF['tor_proxy'][random.randint(0,len(CONF['tor_proxy'])-1)].split(":")
            proxy[1] = int(proxy[1])

        conn = Connection((address, port),
                          (CONF['source_address'], 0),
                          magic_number=network_data['magic_number'],
                          socket_timeout=CONF['tor_socket_timeout'] if address.endswith(".onion") else CONF['socket_timeout'],
                          proxy=proxy,
                          protocol_version=int(network_data['protocol_version']),
                          min_protocol_version=network_data['min_protocol_version'],
                          to_services=int(to_services),
                          from_services=int(from_services or network_data['services']),
                          user_agent=user_agent or CONF['user_agent'],
                          height=int(network_data['height']),
                          relay=CONF['relay'])

        try:
            conn.open()
        except (ProtocolError, ConnectionError, socket.error) as err:
            results['error'] = str(err)
            offline = True
            print("connection failed %s %s,remote peer may be offline", type(err), err)
        else:
            try:
                handshake_msgs = conn.handshake()
                assert handshake_msgs
                results['seen'] = 1
                results['height'] = int(handshake_msgs[0]['height'])
                results['version'] = int(handshake_msgs[0]['version'])
                results['user_agent'] = handshake_msgs[0]['user_agent'].decode()
                results['services'] = int(handshake_msgs[0]['services'])
                results['relay'] = int(handshake_msgs[0]['relay'])
            except (ProtocolError, ConnectionError, socket.error, AssertionError) as err:
                handshake_fail = True
                results['error'] = str(err)
                print("handshake failed, {}".format(err))
        conn.close()
        return offline,handshake_fail,breaked,results
    except Exception as err:
        print("network:{},address:{},port:{}".format(network,address,port))
        print("unspecified connection error: {}".format(err))
        return offline,handshake_fail,breaked,results


def version_filter(addr_a,addr_b):
    addressA, portA = bitnodes_code_ip(addr_a)
    addressB, portB = bitnodes_code_ip(addr_b)
    l,ll,lll,results1 = connect(network, addressA, int(portA), network_data['services'], network_data, None, False, None, False, 1)
    l, ll, lll, results2 = connect(network, addressB, int(portB), network_data['services'], network_data, None, False,None, False, 1)
    if results1['seen'] == 0 and results1['attempt'] < 5:
        l, ll, lll, results1 = connect(network, addressA, int(portA), network_data['services'], network_data, None,False, None, False, 1)
    if results2['seen'] == 0 and results2['attempt'] < 5:
        l, ll, lll, results2 = connect(network, addressB, int(portB), network_data['services'], network_data, None, False,None, False, 1)
    if results1['seen'] and results2['seen']:
        if results1['version']==results2['version'] and results1['user_agent']==results2['user_agent'] \
            and results1['services']==results2['services'] and results1['relay']==results2['relay']:
            return True
        else:
            return False
    else:
        return ""


if __name__ == "__main__":
    target_set = ['81.88.221.*:8333','xlrtxftctoonthjefhukm5kyig7kb33kqvu2xbhmjhyyffbyinixtiad.onion:8333',
                  '193.32.127.*:60969',
                  'astsrlifm7bvjxsi4yampqfrlnf76efexa55l56rx4kzofewugbq26ad.onion:8333',
                  'pbtnuos6vsy4hqwq4ljyfvrtnbrayy62frlgooyv46sqafnu2sczugid.onion:8333',
                  'az6tz7n36wym4w46no4fxc5rmnnmirjqlamtuck5fqxiezyicmcarsqd.onion:8333','108.26.60.*:8333',
                  '[2001:a61:12f4:d201:*]:8333','pcxlvkgabsowmrx54b5bgqglershgfchr6xavrhbfngridplzhf2pwqd.onion:8333',
                  '[2001:4dd0:3564:1:*]:8333',
                  'g3f4ih3b2jzhvyxtaqwdb4y3y564h3xjjsvor5r2tkmtz3sm47jscwqd.onion:8333','195.123.239.*:8333',
                  'o4tyjzd353yvvmpxpc73rdiagcfxocl3kknz3xqq7ugjarxfny73dvyd.onion:8333','[2604:7c00:120:4b:*]:8333',
                  '[2a00:d880:5:c2:*]:8333','173.164.210.*:8333','95.165.104.*:8333',
                  '66.205.103.*:8333','139.59.130.*:8333']
    log_file = 'tests/version_filter/result.log'
    logger = get_logger('A', log_file)
    logger.info("------- This is a line ---------")

    for i in range(0, len(target_set)):
        for j in range(i+1,len(target_set)):
            flag = version_filter(target_set[i],target_set[j])
            if flag == "":
                logger.info(target_set[i]+" "+target_set[j]+" "+"未获取到version信息")
            else:
                logger.info(target_set[i]+" "+target_set[j]+" "+str(flag))
