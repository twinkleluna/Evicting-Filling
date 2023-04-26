# -*- coding: utf-8 -*-
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from app import CONF,to_json
from crawler import bitnodes_code_ip
import time
import random
from protocol import ProtocolError, Connection, ConnectionError, Keepalive
import socket
import logging
import os
import shodan
import json
import datetime


filePath = '/home/ubuntu/opennodes/cache_info/'

def connect(network, address, port, to_services, network_data, user_agent=None, explicit_p2p=False, p2p_nodes=True,
            from_services=None, keepalive=False, attempt=1, filter_interval=6 * 60 * 60):
    now = datetime.datetime.utcnow()
    results = {'network': network, 'address': address, 'port': port, 'timestamp': now, 'seen': 0, 'attempt': attempt}

    try:
        handshake_msgs = []
        new_addrs = []

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
            logging.debug("connection failed %s %s", type(err), err)
        else:
            try:
                handshake_msgs = conn.handshake()
                assert handshake_msgs
                results['seen'] = 1
                results['height'] = int(handshake_msgs[0]['height'])
                results['version'] = int(handshake_msgs[0]['version'])
                results['user_agent'] = handshake_msgs[0]['user_agent'].decode()
                results['services'] = int(handshake_msgs[0]['services'])
            except (ProtocolError, ConnectionError, socket.error, AssertionError) as err:
                results['error'] = str(err)
                logging.debug("handshake failed %s", err)

            msgs = []
            if len(handshake_msgs) > 0 and (p2p_nodes or explicit_p2p):
                #增加rtt的测量
                t1 = time.time()
                conn.ping()
                conn.get_messages(commands=[b"pong"])
                t2 = time.time()
                results['rtt'] = t2-t1
            if keepalive:
                Keepalive(conn, 10).keepalive(addr=True if p2p_nodes else False)
        conn.close()
        return results, new_addrs
    except Exception as err:
        logging.info("network:{},address:{},port:{}".format(network,address,port))
        logging.warning("unspecified connection error: %s", err)
        return {}, []

def get_rtt(targets):
    thread_pool = ThreadPoolExecutor(max_workers=5)
    network = "bitcoin"
    network_data = CONF['networks'][network]
    network_data['height'] = 708175
    futures_dict = {}

    for i in range(len(targets)):
        ip,port = bitnodes_code_ip(targets.iloc[i, targets.columns.get_loc('address')])
        future = thread_pool.submit(connect, network, ip, int(port), network_data['services'],
                                        network_data, filter_interval=0)
        futures_dict["{}|{}|{}".format(network, ip, port)] = future
        time.sleep(0.001)

    n = 0
    while len(futures_dict) > 0:
        time.sleep(1)
        for i in list(futures_dict.keys()):
            if not futures_dict[i].done():
                continue

            future = futures_dict.pop(i)
            result, new_addrs = future.result()
            if not result:
                continue
            if result['seen']:
                n = n + 1
                targets.iloc[targets.index[targets['address']==result['address']+":"+str(result['port'])],targets.columns.get_loc('rtt')]=result['rtt']
            elif not result['seen'] and result['attempt'] < 2:
                future = thread_pool.submit(connect, result["network"], result["address"], result["port"],
                                            network_data['services'],
                                            network_data, attempt=result['attempt'] + 1, filter_interval=0)
                futures_dict["{}|{}|{}".format(result["network"], result["address"], result["port"])] = future
                continue
            else:
                print("{}:{}".format(result['address'],result['port']))
                pass
    return targets

def get_networkfp(targets):
    key = 'Vueflure7rH29Avpgr7gxgoS7Hy9rml0'
    api = shodan.Shodan(key)  # 传入API key，开启API

    for i in range(len(targets)):
        ip,port = bitnodes_code_ip(targets.iloc[i, targets.columns.get_loc('address')])
        try:
            info = api.host(ip)
        except shodan.exception.APIError:
            continue
        os = info['os']
        fingerprint = {}
        for j in info['data']:
            if not j.get('version'):
                j['version'] = "NULL"
            fingerprint[str(j['port'])] = [j['_shodan']['module'], j['version']]
        targets.iloc[i, targets.columns.get_loc('fp')] = json.dumps(fingerprint)
        targets.iloc[i, targets.columns.get_loc('os')] = json.dumps(os)
    return targets


if __name__ == "__main__":
    # targets = pd.read_excel(os.path.join(filePath,'history_collision_normal.xlsx'),names=['key','address','timestamp','height','version','user_agent','services','rtt','addrs','simhash','adj'],engine='openpyxl')
    # # get_rtt(targets)
    # targets = get_rtt(targets)
    # targets['fp'] = ""
    # targets['os'] = ""
    targets = pd.read_excel(os.path.join(filePath, 'history_collision_update.xlsx'),engine='openpyxl')
    targets = get_networkfp(targets)
    targets.to_excel(filePath + 'history_collision_update_2.xlsx')