from crawl_nodes import connect_db
import datetime,openpyxl,getopt,nmap,time
from concurrent.futures import ThreadPoolExecutor
from models import Node
from sqlalchemy import and_, or_
import json
import sys

target_conn = 15

def processing_nodes(session):
    print('#*# Nmap 正在运行')
    futures_dict = {}
    thread_pool = ThreadPoolExecutor(max_workers=target_conn)
    nodes = session.query(Node).filter(and_(Node.date==datetime.datetime.now().strftime("%Y-%m-%d"), or_(Node.w_tried == 0,and_(Node.w_tried < 2,Node.wfp == None)))).all()
    while nodes:
        node = nodes.pop(0)
        if not "onion" in node.address and not "b32.i2p" in node.address:
            future = thread_pool.submit(nmap_thread, node.address)
            futures_dict["{}|{}".format(node.address, node.port)] = node, future
        else:
            pass

    checked_nodes = 0
    total_to_complete = len(futures_dict)
    print(total_to_complete)
    if total_to_complete == 0:
        time.sleep(300)

    while len(futures_dict) > 0:
        for i in list(futures_dict.keys()):
            if not futures_dict[i][1].done():
                continue
            checked_nodes += 1
            if checked_nodes % 10 == 0:
                print("checked: {}%".format(round(checked_nodes / total_to_complete * 100.0, 1)))
            node, future = futures_dict.pop(i)
            os, lastboot, portlist = future.result()
            wfp = {}
            if lastboot:
                wfp['lastboot'] = lastboot
            if portlist:
                wfp['portlist'] = portlist
            node.os = os if os else None
            node.wfp = json.dumps(wfp) if wfp else None
            node.w_tried += 1
            print(node.address)
            session.commit()
    return


def nmap_thread(ip):
    nm = nmap.PortScanner()
    if ":" in ip:
        tmp = nm.scan(hosts=ip, arguments=' -6 -Pn -O --top-ports 1000')
    else:
        tmp = nm.scan(hosts=ip, arguments=' -Pn -O --top-ports 1000')

    portlist = {}
    lastboot, os = '', ''
    try:
        lastboot = tmp['scan'][ip]['uptime']['lastboot']
    except:
        pass
    # 取操作系统类型，因为有些识别不到操作系统，所以用了try避免报错程序结束
    try:
        os = tmp['scan'][ip]['osmatch'][0]['name']
    except:
        pass
    try:
        for p in tmp['scan'][ip]['tcp'].keys():
            portlist[p] = tmp['scan'][ip]['tcp'][p]['name']
    except:
        pass
    return os, lastboot, portlist


if __name__ == '__main__':
    session = connect_db()

    if "--loop" in sys.argv:
        while True:
            starttime = datetime.datetime.now()
            processing_nodes(session)
            endtime = datetime.datetime.now()
            print('耗时：' + str((endtime - starttime).seconds) + 's')