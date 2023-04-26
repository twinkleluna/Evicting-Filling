import requests
import json
import sys
from concurrent.futures import ThreadPoolExecutor
import time
from config import root_path,load_config
import random
import datetime
from protocol import ProtocolError, Connection, ConnectionError, Keepalive
import socket
import logging

CONF = load_config()

def to_json(d):
    """
    Sanitizes a dictionary - converts datetime.datetime instances to timestamps
    :param d: dictionary
    :return: json string
    """
    d = clean_dates(d)
    return json.dumps(d)

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
                #getaddr
                getaddr = True
                if getaddr:
                    for i in range(0,3):
                        try:
                            conn.getaddr(block=False)
                            msgs = msgs + conn.get_messages(commands=[b"addr"])
                        except (ProtocolError, ConnectionError, socket.error) as err:
                            logging.debug("getaddr failed %s", err)
                            break
                        if msgs and msgs[-1]['count'] > 10:
                            break
            if keepalive:
                Keepalive(conn, 10).keepalive(addr=True if p2p_nodes else False)
            if msgs and msgs[-1]['count'] > 10:
                msg = msgs[-1]
                ts = now.timestamp()
                for addr in msg['addr_list']:
                    if filter_interval == 0:
                        n = addr['ipv4'] or addr['ipv6'] or addr['onion']
                        new_addrs.append({'a': n + ':' + str(addr['port']), 't': addr['timestamp'],
                                              's': addr['services']})
                    elif ts - addr['timestamp'] < filter_interval:  # within 6 hours
                        n = addr['ipv4'] or addr['ipv6'] or addr['onion']
                        new_addrs.append({'a': n + ':' + str(addr['port']), 't': addr['timestamp'],
                                              's': addr['services']})
        conn.close()
        return results, new_addrs
    except Exception as err:
        logging.info("network:{},address:{},port:{}".format(network,address,port))
        logging.warning("unspecified connection error: %s", err)
        return {}, []


def cache_acquisition(target_nodes,timestamp,excluded_nodes):
    thread_pool = ThreadPoolExecutor(max_workers=30)
    network = "bitcoin"
    network_data = CONF['networks'][network]
    network_data['height'] = 708175
    futures_dict = {}
    resp = {}

    for address in target_nodes:
        ip,port = bitnodes_code_ip(address)
        if "{}:{}".format(ip,port) not in excluded_nodes:
            future = thread_pool.submit(connect, network, ip, int(port), network_data['services'],
                                        network_data, filter_interval=0)
            futures_dict["{}|{}|{}".format(network, ip, port)] = future
            time.sleep(0.001)
        else:
            continue

    n = 0
    checked_nodes = 0
    total_to_complete = len(futures_dict)

    while len(futures_dict) > 0:
        time.sleep(1)
        for i in list(futures_dict.keys()):
            if not futures_dict[i].done():
                continue
            checked_nodes += 1
            if checked_nodes % 200 == 0:
                print("checked: {}%".format(round(checked_nodes/total_to_complete * 100.0, 1)))
            future = futures_dict.pop(i)
            result, new_addrs = future.result()
            if not result:
                continue
            if result['seen'] and new_addrs:
                excluded_nodes.append("{}:{}".format(result['address'],result['port']))
                n = n + 1
                store_fmt = {}
                store_fmt['info'] = result
                store_fmt['new_addrs'] = new_addrs
                resp["{}:{}".format(result['address'],result['port'])] = store_fmt
            elif result['seen'] and result['attempt'] < 3:
                future = thread_pool.submit(connect, result["network"], result["address"], result["port"],
                                            network_data['services'],
                                            network_data, attempt=result['attempt'] + 1, filter_interval=0)
                futures_dict["{}|{}|{}".format(result["network"], result["address"], result["port"])] = future
                continue
            elif result['seen']:
                store_fmt = {}
                store_fmt['info'] = result
                store_fmt['new_addrs'] = []
                resp["{}:{}".format(result['address'],result['port'])] = store_fmt
            elif not result['seen'] and result['attempt'] < 1:
                future = thread_pool.submit(connect, result["network"], result["address"], result["port"],
                                            network_data['services'],
                                            network_data, attempt=result['attempt'] + 1, filter_interval=0)
                futures_dict["{}|{}|{}".format(result["network"], result["address"], result["port"])] = future
                continue
            else:
                print("{}:{}".format(result['address'],result['port']))
                pass

    path = root_path + 'cache_info/' + str(timestamp) + ".log"
    js_store = to_json(resp)
    with open(path, 'w+') as f:
        f.write(js_store)
        f.close()
    return n,len(resp),len(target_nodes)


def filter_nodes(all_nodes):
    target_nodes = []
    for addr in all_nodes:
        if "Satoshi:22.0.0" in all_nodes[addr][1]:
            target_nodes.append(addr)
    return target_nodes


if __name__ == "__main__":
    # if "--loop" in sys.argv:
    #     while True:
    #         with open('cache_excluded_nodes.txt','r') as f:
    #             excluded_nodes = json.loads(f.read())
    #         starttime = datetime.datetime.now()
    #         url = "https://bitnodes.io/api/v1/snapshots/latest/"
    #         try:
    #             res = requests.get(url)
    #         except requests.exceptions.ProxyError or requests.exceptions.ConnectionError:
    #             time.sleep(300)
    #             continue
    #         json_str = json.loads(res.text)
    #         timestamp = json_str.get("timestamp")
    #         all_nodes = json_str.get("nodes")
    #         target_nodes = filter_nodes(all_nodes)
    #         addrs_count,resp_count,all_count = cache_acquisition(target_nodes,timestamp,excluded_nodes)
    #         print(addrs_count)
    #         print(resp_count)
    #         print(len(excluded_nodes))
    #         print(all_count)
    #         endtime = datetime.datetime.now()
    #         with open('cache_excluded_nodes.txt','w+') as f:
    #             f.write(json.dumps(excluded_nodes))
    #         print('耗时：' + str((endtime - starttime).seconds) + 's')
    network_data = CONF['networks']['bitcoin']
    network_data['height'] = 706121
    targets = ['2001:4b98:dc0:45:*','2a01:4f9:4b:1d11:*','2001:41d0:800:2b9e:*','2a01:4f8:201:8062:*',
               '2a01:238:4389:c400:*','2604:a880:cad:d0:*c0b:f001','2a01:4f9:3b:3de4:*','2001:41d0:303:dc77:*',
               '2a01:4f8:150:30d5:*','2a00:13a0:3015:1:*','2a01:4f9:6b:118a:*','2a01:4f9:4a:5188:*','2a02:c206:2082:1246:*',
               '2a01:490:16:301:*','2001:41d0:303:dc77:*','2a01:4f8:160:7290:*','2a03:4000:66:ccc:*','2a10:3781:16b9:1:*',
               '2001:1b28:801:2423:*','2a01:4f9:c011:9ca0:*','2a01:4f8:252:115:*','2a01:4f9:3b:3de4:*','2a01:4f8:120:82cd:*',
               '2001:41d0:403:4a65:*','2a01:4f8:241:1eea:*','2a01:4f9:2a:9e7:*','2a01:4f8:211:a58:*','2a01:4f9:6b:294b:*','2a01:4f9:1a:9015:*',
               '2a02:c206:3008:2368:*','2a01:4f8:151:108b:*','2a01:4f8:251:5249:*','2a01:4f9:3a:40e4:*','2620:11c:5001:1118:*',
               '2a03:4000:6:7348:*','2a01:e0a:252:6bd0:*','2a07:5741:0:1152:*','2a04:3544:1000:1510:*','2001:bc8:323c:100:*',
               '2a01:4f8:151:5149:*','2a01:4f8:160:5415:*']
    decords = {}
    for i in targets:
        results, new_addrs = connect('bitcoin', i, 8333, network_data['services'], network_data, filter_interval=0)
        decords[i]={'addrs':new_addrs}
        with open('large_scale_experiment/results/compare/addrs.txt','w+') as f:
            f.write(json.dumps(decords))
            f.close()