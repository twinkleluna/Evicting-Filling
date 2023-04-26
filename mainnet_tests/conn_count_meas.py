import socket
import time
import threading
from connpool_protocol import ProtocolError, Connection, ConnectionError
from config import load_config
import random
import logging
import sys
from sqlalchemy import create_engine,and_,or_
from sqlalchemy.orm import sessionmaker
from models import Node,Base
import datetime

CONF = load_config()
network = "bitcoin"
network_data = CONF['networks'][network]
network_data['height'] = 706121


def connect_db():
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://***:******@*.*.*.*:3306/idbitnodes'
    engine = create_engine(SQLALCHEMY_DATABASE_URI, echo=False)
    Base.metadata.create_all(engine)
    Sess = sessionmaker(bind=engine, autoflush=False)
    return Sess()


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


def get_nodes(session,date,offset,count):
    q = session.query(Node).filter(Node.date == date).offset(offset).limit(count)
    nodes = q.all()
    total_to_complete = q.count()
    return nodes,total_to_complete


if __name__ == "__main__":
    offset = sys.argv[1]  ## 第一个参数
    count = sys.argv[2]  ## 第二个参数

    starttime = datetime.datetime.now()
    log_file = 'tests/conn_count_meas/220302/'+str(offset)+'-'+str(count)+'.log'
    logger = get_logger('Result', log_file)

    session = connect_db()
    date = "2022-03-02"
    target_nodes,total_to_complete = get_nodes(session, date, offset, count)
    mutex = threading.Lock()
    print(target_nodes)
    print(total_to_complete)

    checked_nodes = 0
    while target_nodes:
        node = target_nodes.pop(0)
        if node.connslots != None and node.connslots != 0:
            continue
        success_counts1,fail_counts1,tried1 = 0,0,0
        stop_threads = False
        stable_activeCount,threads1 = empty_slots_count(node.address, node.port)
        stop_threads = True
        for thr1 in threads1:
            thr1.join()
        while threading.activeCount()!=1:
            time.sleep(3)
        node.connslots = stable_activeCount
        session.commit()

        checked_nodes += 1
        if checked_nodes % 10 == 0:
            print("checked: {}%".format(round(checked_nodes / total_to_complete * 100.0, 1)))

        endtime = datetime.datetime.now()
        logger.info(" " + encode_ip(node.address, node.port) + " " + str(stable_activeCount) + " slots")
        logger.info('耗时：' + str((endtime - starttime).seconds) + 's')
