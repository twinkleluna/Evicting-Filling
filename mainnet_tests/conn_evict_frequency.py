import socket
import time
import threading
from connpool_protocol import ProtocolError, Connection, ConnectionError
from config import load_config
import random
import logging
import datetime
import sys
import requests
import json

CONF = load_config()
network = "bitcoin"
network_data = CONF['networks'][network]
network_data['height'] = 706121


def get_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('[%(asctime)s] %(message)s', "%Y-%m-%d %H:%M:%S")
    fileHandler = logging.FileHandler(log_file, mode='a+')
    fileHandler.setFormatter(formatter)
    l.setLevel(level)
    l.addHandler(fileHandler)
    return logging.getLogger(logger_name)


class Keepalive(object):
    """
    Implements keepalive mechanic to keep the specified connection with a node.
    """
    def __init__(self, conn, keepalive_time):
        self.conn = conn
        self.keepalive_time = keepalive_time

    def keepalive(self, addr=False):
        st = time.time()
        last_ping = time.time() - 10
        addrs = []
        breaked = False
        while time.time() - st < self.keepalive_time:
            if time.time() - last_ping > 9:
                try:
                    self.ping()
                    last_ping = time.time()
                except socket.error as err:
                    print("keepalive failed %s", err)
                    breaked = True
                    break
            global stop_threads
            if stop_threads:
                break
            time.sleep(0.3)
            try:
                if addr:
                    new = self.conn.get_messages(commands=[b'addr'])
                    addrs += new
                else:
                    self.conn.get_messages()
            except socket.timeout:
                pass
            except (ProtocolError, ConnectionError, socket.error) as err:
                print("getmsg failed %s", err)
                breaked = True
                break
        return breaked

    def ping(self):
        """
        Sends a ping message. Ping time is stored in Redis for round-trip time
        (RTT) calculation.
        """
        nonce = random.getrandbits(64)
        try:
            self.conn.ping(nonce=nonce)
        except socket.error:
            raise
        self.last_ping = time.time()


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
            global tried1
            mutex.acquire()
            tried1 += 1
            mutex.release()
            conn.open()
        except (ProtocolError, ConnectionError, socket.error) as err:
            results['error'] = str(err)
            offline = True
        else:
            try:
                handshake_msgs = conn.handshake()
                assert handshake_msgs
                global success_counts1
                mutex.acquire()
                success_counts1 += 1
                mutex.release()
                results['seen'] = 1
                results['height'] = int(handshake_msgs[0]['height'])
                results['version'] = int(handshake_msgs[0]['version'])
                results['user_agent'] = handshake_msgs[0]['user_agent'].decode()
                results['services'] = int(handshake_msgs[0]['services'])
                if keepalive:
                    breaked = Keepalive(conn, 60 * 30).keepalive(addr=False)
            except (ProtocolError, ConnectionError, socket.error, AssertionError) as err:
                handshake_fail = True
                results['error'] = str(err)
        conn.close()
        if breaked:
            global fail_counts1
            mutex.acquire()
            fail_counts1 += 1
            mutex.release()
        return offline,handshake_fail,breaked
    except Exception as err:
        return offline,handshake_fail,breaked


def encode_ip(address,port):
    if ".onion" in address:
        # onion
        inp = address+":"+str(port)
    elif "." in address:
        # IPv4
        inp = address+":"+str(port)
    else:
        #IPv6
        inp = "["+address+"]:"+str(port)
    return inp


def empty_slots_count(address, port):
    target_conn = 115
    threads1 = []
    for i in range(0,target_conn):
        thr1 = threading.Thread(target=connect, args=(network, address, int(port), network_data['services'],network_data,None, False, None, True, 1))
        threads1.append(thr1)
        thr1.setDaemon(True)
        thr1.start()
        time.sleep(0.001)

    last_activeCount = success_counts1 - fail_counts1
    num = 0
    if "onion" in address:
        interval1 = 10
        time.sleep(60)
    else:
        interval1 = 5
    st = time.time()
    while True:
        if time.time() - st > interval1:
            stable_activeCount = success_counts1 - fail_counts1
            st = time.time()
            if tried1 == target_conn and stable_activeCount >= last_activeCount-1 and num <= 2:
                num += 1
            elif tried1 == target_conn and stable_activeCount >= last_activeCount-1:
                break
            else:
                last_activeCount = stable_activeCount

    return stable_activeCount,threads1


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


def catch_bitnodes():
    url = "https://bitnodes.io/api/v1/snapshots/latest/"
    try:
        res = requests.get(url)
    except requests.exceptions.ProxyError or requests.exceptions.ConnectionError:
        print("anything wrong with api requests")
        return
    json_str = json.loads(res.text)
    nodes_value = json_str.get("nodes")
    nodes = []
    for IPport in nodes_value.keys():
        if not "Satoshi:22.0.0" in nodes_value[IPport][1]:
            continue
        nodes.append(IPport)
    return nodes


if __name__ == "__main__":
    if "--loop" in sys.argv:
        # our_nodes = ['49.233.16.*:8333','101.43.219.*:8333',
        #              '101.33.80.*:8333','43.132.198.*:8333',
        #              'iybou5eoyg45ufbyrnrlif3ektrxej3b2v4v5wcyq6d7bugk3wj7smid.onion:8333',]
        target_nodes = [
                        '168.119.186.*:8333',
                        'afpk3ick2scmromlamykmdzeqgjifa3jjzlfxqlcy2fyy3n3rcu463qd.onion:8333',
                        '217.138.199.*:56805',
                        'pbtnuos6vsy4hqwq4ljyfvrtnbrayy62frlgooyv46sqafnu2sczugid.onion:8333',
                        '95.165.104.*:8333',
                        '217.138.199.*:56805',
                        'a7n3hcltl4jhy6uvoh4lnkk6ti5tlnsm52icv6yjxd722z5cc5asq5qd.onion:8333',
                        '91.210.24.*:8333',
                        'xlrtxftctoonthjefhukm5kyig7kb33kqvu2xbhmjhyyffbyinixtiad.onion:8333',
                        '210.54.39.*:8333',
                        'hlo6xr4kslyhntlz5mfo2jgfnznnppajsyatnfiaofvsiqdd35kvlcad.onion:8333',
                        '139.59.130.*:8333',
                        '6ygbmwqohdq3igfafsqduchgbilfld3sarvqcf6homd5ueclkuqhraid.onion:8333',
                    ]
        # target_nodes2 = ['74.79.123.*:8333',
        #                 '81.88.221.*:8333',
        #                 '173.164.210.*:8333',
        #                 'etmlnokcnfvmfk4yo2ggogaqkozu5nvdmgs4x25av6izssbbpsrfauid.onion:8333',
        #                 '81.4.100.*:8333',
        #                 '66.205.103.*:8333',
        #                 '[2001:4dd0:3564:0:*]:8333',
        #
        #                 'jhana24s3dzkitzp.onion:8333',
        #                 'gjf6rkeopgbqmttguev2wb2yupv7t5eyfwtzdamncja34c5yhxrztpid.onion:8333',
        #                 'cb5aivblk7tqcrnll4kcn4l5jmrlkjgvdozuzgdw4tu6etzectyaggqd.onion:8333',
        #                 '205.201.123.*:8333',
        #                 '195.123.239.*:8333',
        #                 'buddhovmm6ctfzz6et6jul5amux34df6fqmbk5qush3xzmqo2vjvnvyd.onion:8333',
        #                 '[2001:4dd0:3564:1:*]:8333',
        #                 '[2001:4dd0:3564:0:*]:8333',
        #                 '[2001:4dd0:3564:1:*]:8333',
        #                 '46.227.115.*:8333',
        #                 '[2001:4dd0:3564:0:*]:8333',
        #                 'xip3yk4mjopez27akkupef33wauxlw4ak6t5qhaspxjgbxgr6pfnu7id.onion:8333',
        #   ]

        # target_nodes = catch_bitnodes()

        log_file = 'tests/conn_evict_freq/220306/' + str(target_nodes[0]) + '-' + str(target_nodes[-1]) + '.log'
        logger = get_logger('Result', log_file)
        while True:
            starttime = datetime.datetime.now()
            mutex = threading.Lock()

            for node in target_nodes:
                # if (node in target_nodes1) or (node in target_nodes2) or (node in our_nodes):
                #     continue
                address, port = bitnodes_code_ip(node)
                success_counts1,fail_counts1,tried1 = 0,0,0
                stop_threads = False
                last_activeCount,threads1 = empty_slots_count(address, port)
                logger.info(encode_ip(address, port) + ": " + str(last_activeCount) + " empty slots")
                if last_activeCount == 0:
                    continue

                for q in range(0,7):
                    time.sleep(60)
                    now_activeCount = success_counts1 - fail_counts1
                    if now_activeCount == 0:
                        break
                    lost = last_activeCount - now_activeCount
                    logger.info(encode_ip(address, port) + ": " + str(now_activeCount) + " slots, lost: "+str(lost))
                    last_activeCount = now_activeCount
                stop_threads = True
                for thr1 in threads1:
                    thr1.join()
                while threading.activeCount()!=1:
                    time.sleep(3)
            endtime = datetime.datetime.now()
            logger.info('耗时：' + str((endtime - starttime).seconds) + 's')
