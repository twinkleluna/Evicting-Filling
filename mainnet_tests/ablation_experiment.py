import datetime
import json
import socket
import time
import threading
from connpool_protocol import ProtocolError, Connection, ConnectionError
from config import load_config
import random
import sys
import logging
import math


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
                breaked = True
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


def connect(id, logger, network, address, port, to_services, network_data, user_agent=None, p2p_nodes=True,
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
            if id == 1:
                global tried1
                mutex.acquire()
                tried1 += 1
                mutex.release()
            elif id == 2:
                global tried2
                mutex.acquire()
                tried2 += 1
                mutex.release()
            elif id == 3:
                global tried3
                mutex.acquire()
                tried3 += 1
                mutex.release()
            conn.open()
        except (ProtocolError, ConnectionError, socket.error) as err:
            results['error'] = str(err)
            offline = True
            logger.info("connection failed %s %s,remote peer may be offline", type(err), err)
        else:
            try:
                handshake_msgs = conn.handshake()
                assert handshake_msgs
                if id == 1:
                    global success_counts1
                    mutex.acquire()
                    success_counts1 += 1
                    mutex.release()
                elif id == 2:
                    global success_counts2
                    mutex.acquire()
                    success_counts2 += 1
                    mutex.release()
                elif id == 3:
                    global success_counts3
                    mutex.acquire()
                    success_counts3 += 1
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
                logger.info("handshake failed, {}".format(err))
        conn.close()
        if breaked:
            if id == 1:
                global fail_counts1
                mutex.acquire()
                fail_counts1 += 1
                mutex.release()
            elif id == 2:
                global fail_counts2
                mutex.acquire()
                fail_counts2 += 1
                mutex.release()
            elif id == 3:
                global fail_counts3
                mutex.acquire()
                fail_counts3 += 1
                mutex.release()
        return offline,handshake_fail,breaked
    except Exception as err:
        logger.info("network:{},address:{},port:{}".format(network,address,port))
        logger.info("unspecified connection error: {}".format(err))
        return offline,handshake_fail,breaked


def code_ip_type(inp):
    if ".onion" in inp:
        return "Onion"
    elif "." in inp:
        return "IPv4"
    elif ":" in inp:
        return "IPv6"
    else:
        return "Unknown"


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


def connpool_validation_first(addr_a,addr_b):
    # addr_a = sys.argv[1]  ##脚本名
    # addr_b = sys.argv[2]  ## 第一个参数
    log_file1 = 'tests/ablation_experiment/220616/'+addr_a+'_1.log'
    log_file2 = 'tests/ablation_experiment/220616/'+addr_b+'_1.log'
    logger1 = get_logger('A', log_file1)
    logger2 = get_logger('B', log_file2)
    logger1.info("------- "+addr_a+" "+addr_b+" First Stage ---------")
    logger2.info("------- "+addr_a+" "+addr_b+" First Stage ---------")

    addressA, portA = bitnodes_code_ip(addr_a)
    addressB, portB = bitnodes_code_ip(addr_b)
    target_conn = 115

    threads1 = []
    for i in range(0,target_conn):
        thr1 = threading.Thread(target=connect, args=(1, logger1, network, addressA, int(portA), network_data['services'],network_data,None, False, None, True, 1))
        threads1.append(thr1)
        thr1.setDaemon(True)
        thr1.start()
        time.sleep(0.001)

    last_activeCount = success_counts1 - fail_counts1
    num = 0
    if "onion" in addr_a:
        interval1 = 10
        time.sleep(60)
    else:
        interval1 = 5
    st = time.time()
    while True:
        if time.time() - st > interval1:
            stable_activeCount = success_counts1 - fail_counts1
            logger1.info("there are " + str(success_counts1 - fail_counts1) + " connections at " + str(time.time()))
            st = time.time()
            if tried1 == target_conn and stable_activeCount >= last_activeCount-1 and num <= 2:
                num += 1
            elif tried1 == target_conn and stable_activeCount >= last_activeCount-1:
                break
            else:
                last_activeCount = stable_activeCount

    # for q in range(0,20):
    #     time.sleep(5)
    #     logger1.info("there are " + str(success_counts1 - fail_counts1) + " connections at " + str(time.time()))

    threads2 = []
    for i in range(0,target_conn):
        thr2 = threading.Thread(target=connect, args=(2, logger2, network, addressB, int(portB), network_data['services'],network_data,None, False, None, True, 1))
        threads2.append(thr2)
        thr2.setDaemon(True)
        thr2.start()
        time.sleep(0.001)

    last_activeCount2 = success_counts2 - fail_counts2
    num = 0
    if "onion" in addr_b:
        interval2 = 10
        time.sleep(60)
    else:
        interval2 = 5
    st = time.time()
    while True:
        if time.time() - st > interval2:
            first_activeCount = success_counts1 - fail_counts1
            logger1.info("there are " + str(first_activeCount) + " connections at " + str(time.time()))
            stable_activeCount2 = success_counts2 - fail_counts2
            logger2.info("there are " + str(stable_activeCount2) + " connections at " + str(time.time()))
            st = time.time()
            if tried2 == target_conn and stable_activeCount2 >= last_activeCount2-1 and num <= 2:
                num += 1
            elif tried2 == target_conn and stable_activeCount2 >= last_activeCount2-1:
                break
            else:
                last_activeCount2 = stable_activeCount2

    logger.info("First phase, we establish "+str(stable_activeCount)+" connections to address "+addr_a+". Then, we establish "+str(stable_activeCount2)
          +" connections to address "+addr_b+", and connections to address "+addr_a+" dropped to "+str(first_activeCount)+".")

    return stable_activeCount,stable_activeCount2,first_activeCount,threads1,threads2

def connpool_validation_second(addr_a,addr_b):
    log_file3 = 'tests/ablation_experiment/220616/'+addr_b+'_2.log'
    logger3 = get_logger('B2', log_file3)
    logger3.info("------- " + addr_a + " " + addr_b + " Second Stage ---------")

    addressB, portB = bitnodes_code_ip(addr_b)
    target_conn = 115

    threads3 = []
    for i in range(0,target_conn):
        thr3 = threading.Thread(target=connect, args=(3, logger3, network, addressB, int(portB), network_data['services'],network_data,None, False, None, True, 1))
        threads3.append(thr3)
        thr3.setDaemon(True)
        thr3.start()
        time.sleep(0.001)

    last_activeCount = success_counts3 - fail_counts3
    if "onion" in addr_b:
        interval3 = 30
        time.sleep(60)
    else:
        interval3 = 15
    while True:
        time.sleep(interval3)
        stable_activeCount = success_counts3 - fail_counts3
        logger3.info("there are " + str(success_counts3 - fail_counts3) + " connections at " + str(time.time()))
        if tried3 == target_conn and stable_activeCount >= last_activeCount - 1:
            break
        else:
            last_activeCount = stable_activeCount

    logger.info("Second phase, we establish " + str(stable_activeCount) + " connections to address " + addr_b +".")
    return stable_activeCount,threads3

def ablation_character_two(addr_a,addr_b):
    log_file1 = 'tests/ablation_experiment/220616/' + addr_a + '_1.log'
    logger1 = get_logger('aba2', log_file1)
    logger1.info("------- " + addr_a + " " + addr_b + " Character two ---------")
    log_file2 = 'tests/ablation_experiment/220616/'+addr_b+'_1.log'
    logger2 = get_logger('abb2', log_file2)
    logger2.info("------- " + addr_a + " " + addr_b + " Character two ---------")

    addressA, portA = bitnodes_code_ip(addr_a)
    addressB, portB = bitnodes_code_ip(addr_b)
    target_conn = 115

    threads1 = []
    for i in range(0,target_conn):
        thr1 = threading.Thread(target=connect, args=(1, logger1, network, addressA, int(portA), network_data['services'],network_data,None, False, None, True, 1))
        threads1.append(thr1)
        thr1.setDaemon(True)
        thr1.start()
        time.sleep(0.001)
    last_activeCount1 = success_counts1 - fail_counts1
    if "onion" in addr_a:
        interval = 30
        time.sleep(60)
    else:
        interval = 15
    while True:
        time.sleep(interval)
        stable_activeCount1 = success_counts1 - fail_counts1
        logger1.info("there are " + str(success_counts1 - fail_counts1) + " connections at " + str(time.time()))
        if tried1 == target_conn and stable_activeCount1 >= last_activeCount1 - 1:
            break
        else:
            last_activeCount1 = stable_activeCount1

    global stop_threads
    stop_threads = True
    for thr1 in threads1:
        thr1.join()


    stop_threads = False
    threads2 = []
    for i in range(0,target_conn):
        thr2 = threading.Thread(target=connect, args=(2, logger2, network, addressB, int(portB), network_data['services'],network_data,None, False, None, True, 1))
        threads2.append(thr2)
        thr2.setDaemon(True)
        thr2.start()
        time.sleep(0.001)
    last_activeCount2 = success_counts2 - fail_counts2
    if "onion" in addr_b:
        interval = 30
        time.sleep(60)
    else:
        interval = 15
    while True:
        time.sleep(interval)
        stable_activeCount2 = success_counts2 - fail_counts2
        logger2.info("there are " + str(success_counts2 - fail_counts2) + " connections at " + str(time.time()))
        if tried2 == target_conn and stable_activeCount2 >= last_activeCount2 - 1:
            break
        else:
            last_activeCount2 = stable_activeCount2

    logger.info("In ablation experiment, we can establish " + str(stable_activeCount1) + " connections to address " + addr_a +
                ", and after releasing these connections, we can establish " + str(stable_activeCount2)+" connections to address " + addr_b +".")
    return stable_activeCount1,stable_activeCount2,threads2


if __name__ == "__main__":
    # target_set = ['49.233.16.*:8333','[2402:4e00:1202:fe00:*]:8333',
    #               '101.43.219.*:8333','101.43.219.*:8334',
    #              '101.33.80.*:8333','dzm52lslwpm3qbjxmbftc4dbvk4in2eihbtoife6ybshxnzym2zwe2yd.onion:8333',
    #              '43.132.198.*:8333','[240d:c000:2020:f00:*]:8333','qjrtbxjs3f5f2bw54yz4wvhvk2zlfodad5frifrnlltdzfistu2v5pqd.onion:8333',
    #              'iybou5eoyg45ufbyrnrlif3ektrxej3b2v4v5wcyq6d7bugk3wj7smid.onion:8333','iv2zljzmqji7tytsksuprwj7ojp6uv67oq5uv6rymlcqjihpmz5xkmid.onion:8333']
    # target_set = ['94.199.178.*:3201','94.199.178.*:3201']
    # target_set = ['49.233.16.*:8333', '[2402:4e00:1202:fe00:*]:8333',
    #               '101.43.219.*:8333', '101.43.219.*:8334',
    #               '101.33.80.*:8333', 'dzm52lslwpm3qbjxmbftc4dbvk4in2eihbtoife6ybshxnzym2zwe2yd.onion:8333',
    #               '43.132.198.*:8333', '[240d:c000:2020:f00:*]:8333','qjrtbxjs3f5f2bw54yz4wvhvk2zlfodad5frifrnlltdzfistu2v5pqd.onion:8333',
    #               'iybou5eoyg45ufbyrnrlif3ektrxej3b2v4v5wcyq6d7bugk3wj7smid.onion:8333','iv2zljzmqji7tytsksuprwj7ojp6uv67oq5uv6rymlcqjihpmz5xkmid.onion:8333',
    #               'astsrlifm7bvjxsi4yampqfrlnf76efexa55l56rx4kzofewugbq26ad.onion:8333','keetg3aczdiegooddj7d6owxevdyd2vsgn2g7p6p6dvhabitdb3linid.onion:8333',
    #               'w3xado5j5gyzw7fglx7q3e2xda233c5t4tipdvhe2walzl5yhpsnbkad.onion:8333','fo5reuotmc5mcopdhazhdhvnc4u4fnvvqdmuskwrayrgdc4sh4uq7uid.onion:8333',
    #               'az6tz7n36wym4w46no4fxc5rmnnmirjqlamtuck5fqxiezyicmcarsqd.onion:8333','pzyzko2ipo5j6gyz46lftdojsqb7e7bgzlwcvmyksluyssiujole6kad.onion:8333',
    #               '81.88.221.*:8333', '109.173.41.*:8333',
    #               '66.205.103.*:8333', '205.201.123.*:8333',
    #               'etmlnokcnfvmfk4yo2ggogaqkozu5nvdmgs4x25av6izssbbpsrfauid.onion:8333','4fykksxeeisvjkcwif76dbz7ac3en3m7yo246b22xvci56kdhj2ckwqd.onion:8333']

    target_set = [['81.88.221.*:8333','109.173.41.*:8333'],
                  ['cvoyfohsxvmtem5goxcj72a3dghdhuvppw3kznjm7fpibvawppfmu6qd.onion:8333','165.227.46.*:8333'],
                  ['77.179.35.*:8333','77.180.4.*:8333'],
                  ['[2a00:d880:5:c2:*]:8333','81.4.100.*:8333','a7n3hcltl4jhy6uvoh4lnkk6ti5tlnsm52icv6yjxd722z5cc5asq5qd.onion:8333'],
                  ['yipidja7f6bglzdbkkh6muj5hqwicow5rtv6chwfd4g2pr6lpf6vseqd.onion:8333','[2604:7c00:120:4b:*]:8333','195.123.239.*:8333','104.129.171.*:8333'],
                  ['199.193.174.*:8333','108.175.15.*:8333'],
                  ['lp4c6tii3hbvsyn44pvsdzho4237wsak4yppnzupepx77fqxqpke42qd.onion:8333','3heremuxxvifb6nzwe2vdjjrbbpmg7b2nctlt45bd3ezpumuhjvl2hid.onion:8333'],
                  ['74.79.123.*:8333','108.26.60.*:8333'],
                  ['217.138.199.*:56805','217.138.199.*:56805','217.138.199.*:56805'],
                  ]

    mutex = threading.Lock()
    log_file = 'tests/ablation_experiment/220616/result.log'
    logger = get_logger('Result', log_file)
    logger.info('-------------- this is a line -------------')

    # 特征一/特征一+特征二
    # for i in range(0, len(target_set)):
    #     for j in range(i+1,len(target_set)):
    for sub in range(0, len(target_set)):
      for i in range(0, len(target_set[sub])):
        for j in range(i + 1, len(target_set[sub])):
            starttime = datetime.datetime.now()
            success_counts1,fail_counts1,tried1 = 0,0,0
            success_counts2,fail_counts2,tried2 = 0,0,0
            success_counts3,fail_counts3,tried3 = 0,0,0
            stop_threads = False
            result1 = False
            result3 = False
            stable_activeCount,stable_activeCount2,first_activeCount,threads1,threads2 = connpool_validation_first(target_set[sub][i],target_set[sub][j])
            # for q in range(0, 20):
            #     time.sleep(5)
            #     logger1.info("there are " + str(success_counts1 - fail_counts1) + " connections at " + str(time.time()))
            #     logger2.info("there are " + str(success_counts2 - fail_counts2) + " connections at " + str(time.time()))
            stop_threads = True
            for thr1 in threads1:
                thr1.join()
            for thr2 in threads2:
                thr2.join()
            while threading.activeCount()!=1:
                time.sleep(3)
            stop_threads = False
            if (stable_activeCount > 23 and math.isclose(stable_activeCount, stable_activeCount2 + first_activeCount,abs_tol=8)) or (stable_activeCount <= 23 and math.isclose(stable_activeCount,stable_activeCount2 + first_activeCount,abs_tol=stable_activeCount * 0.2)):
                stable_activeCount3,threads3 = connpool_validation_second(target_set[sub][i],target_set[sub][j])
                # for q in range(0,20):
                #     time.sleep(5)
                #     logger3.info("there are " + str(success_counts3 - fail_counts3) + " connections at " + str(time.time()))
                result1 = True
                stop_threads = True
                for thr3 in threads3:
                    thr3.join()
                while threading.activeCount() != 1:
                    time.sleep(3)
                # if math.isclose(stable_activeCount, stable_activeCount3, abs_tol=7):
                if (stable_activeCount > 7 and math.isclose(stable_activeCount, stable_activeCount3,abs_tol=7)) or (stable_activeCount < 8 and math.isclose(stable_activeCount, stable_activeCount3,abs_tol=stable_activeCount * 0.2)):
                    result3 = True
            logger.info("特征一： " + target_set[sub][i] + " " + target_set[sub][j] + " " + str(result1))
            logger.info("特征一+特征二： " + target_set[sub][i]+" "+target_set[sub][j]+" "+str(result3))
            endtime = datetime.datetime.now()
            logger.info('耗时：' + str((endtime - starttime).seconds) + 's')

    # 特征二
    # for i in range(0, len(target_set)):
    #     for j in range(i + 1, len(target_set)):
    for sub in range(0, len(target_set)):
      for i in range(0, len(target_set[sub])):
        for j in range(i + 1, len(target_set[sub])):
            starttime = datetime.datetime.now()
            success_counts1, fail_counts1, tried1 = 0, 0, 0
            success_counts2, fail_counts2, tried2 = 0, 0, 0
            result2 = False
            stop_threads = False
            stable_activeCount1, stable_activeCount2, threads2= ablation_character_two(target_set[sub][i], target_set[sub][j])
            stop_threads = True
            for thr2 in threads2:
                thr2.join()
            if (stable_activeCount1 >7  and math.isclose(stable_activeCount1, stable_activeCount2, abs_tol=7)) or (stable_activeCount1 <8 and math.isclose(stable_activeCount1,stable_activeCount2,abs_tol=stable_activeCount1 * 0.2)):
                result2 = True
            logger.info("特征二： " + target_set[sub][i]+" "+target_set[sub][j]+" "+str(result2))
            endtime = datetime.datetime.now()
            logger.info('耗时：' + str((endtime - starttime).seconds) + 's')