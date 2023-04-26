import socket
import time
import os
import datetime
import json
import threading
from simulconn_protocol import ProtocolError, Connection, ConnectionError
from config import load_config
import random
import sys
import logging
import math

CONF = load_config()
network = "bitcoin"
network_data = CONF['networks'][network]
network_data['height'] = 706121

# connected = False
# while not connected:
# try:
#     pid = os.getpid()
#     client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client1.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
#     client1.bind(('', 10805))
#     pid1 = os.fork()
#     # print("1")
#
#     # for i in range(0,2):
#     while True:
#         if pid1 == 0:
#             client1.connect(('127.0.0.*', 8334))
#             data = input(">")
#             if not data:
#                 break
#             client1.send(data.encode())
#             response = client1.recv(1024)
#             print(response)
#         else:
#             client1.connect(('127.0.0.*', 8333))
#             data = input(">")
#             if not data:
#                 break
#             client1.send(data.encode())
#             response = client1.recv(1024)
#             print(response)
# except socket.error as err:
#     print(err)
# client1.close()
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
                if keepalive:
                    breaked = Keepalive(conn, 60 * 30).keepalive(addr=False)
            except (ProtocolError, ConnectionError, socket.error, AssertionError) as err:
                handshake_fail = True
                results['error'] = str(err)
                print("handshake failed, {}".format(err))
        conn.close()
        return offline,handshake_fail,breaked
    except Exception as err:
        print("network:{},address:{},port:{}".format(network,address,port))
        print("unspecified connection error: {}".format(err))
        return offline,handshake_fail,breaked


if __name__ == "__main__":
    addressA = '94.199.178.*'
    portA = 3201
    offline,handshake_fail,breaked = connect(network, addressA, int(portA), network_data['services'], network_data, None, False, None, True, 1)
    print(offline, handshake_fail, breaked)
    # addressB = ''
    # portB = 8333

    # thr1 = threading.Thread(target=connect, args=(network, addressA, int(portA), network_data['services'], network_data, None, False, None, True, 1))
    # thr1.setDaemon(True)
    # thr1.start()
    # thr2 = threading.Thread(target=connect, args=(network, addressB, int(portB), network_data['services'], network_data, None, False, None, True, 1))
    # thr2.setDaemon(True)
    # thr2.start()