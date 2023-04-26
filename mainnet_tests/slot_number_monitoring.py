import os
import time
import json
import logging


def get_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('[%(asctime)s] %(message)s', "%Y-%m-%d %H:%M")
    fileHandler = logging.FileHandler(log_file, mode='a+')
    fileHandler.setFormatter(formatter)
    l.setLevel(level)
    l.addHandler(fileHandler)
    return logging.getLogger(logger_name)


def open_slots():
    peers = []
    peers_num = 0
    output = os.popen('bitcoin-cli -rpcuser=*** -rpcpassword=****** getpeerinfo').read()
    js = json.loads(output)
    for i in js:
        # if i["connection_type"] == "inbound":
            peers.append({'id': i["id"], 'addr': i["addr"]})
            peers_num += 1
    return peers, peers_num

def change_slots(last_peers,peers):
    lost,new = 0,0
    for peer in peers:
        if peer not in last_peers:
            new += 1
    for peer in last_peers:
        if peer not in peers:
            lost += 1
    return lost,new


if __name__ == '__main__':
    time_today = time.strftime("%Y%m%d", time.localtime())
    peer_file = 'tests/slots_monitor/220610/' + time_today + '.log'
    peer_logger = get_logger('Peer', peer_file)

    result_file = 'tests/slots_monitor/220610cd/result.log'
    result_logger = get_logger('Result', result_file)

    last_peers,last_peers_num = open_slots()
    peer_logger.info(str(last_peers_num)+' peers: '+json.dumps(last_peers))
    while True:
        time.sleep(60)
        peers,peers_num = open_slots()
        peer_logger.info(str(peers_num)+' peers: '+json.dumps(peers))
        lost,new = change_slots(last_peers,peers)
        last_peers, last_peers_num = peers,peers_num
        result_logger.info('peers num: '+str(peers_num)+', lost num: '+str(lost)+', new num: '+str(new))
