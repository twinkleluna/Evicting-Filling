#!/usr/bin/python
# -*- coding: UTF-8 -*-
import json
import datetime
from crawl_nodes import code_ip, connect_db, root_path
from models import Node
from sqlalchemy import and_, func
import os


def merge_two_dicts(x, y):
    """Given two dicts, merge them into a new dict as a shallow copy."""
    z = x.copy()
    z.update(y)
    return z

def calculate_syncrate(session):
    file1 = root_path+'nodes_info/'+str(datetime.datetime.now().strftime('%Y%m%d%H'))+'.txt'
    file2 = root_path + 'nodes_info/' + str(
        (datetime.datetime.now()-datetime.timedelta(hours=4)).strftime('%Y%m%d%H')) + '.txt'
    try:
        with open(file1,'r+') as f1:
            json_str1 = json.loads(f1.read())
        with open(file2, 'r+') as f2:
            json_str2 = json.loads(f2.read())
    except FileNotFoundError:
        print(file1)
        print(file2)
        return
    nodes_value1 = json_str1.get("nodes")
    ts1 = json_str1.get("timestamp")
    nodes_value2 = json_str2.get("nodes")
    ts2 = json_str2.get("timestamp")

    # nodes_value = merge_two_dicts(nodes_value1,nodes_value2)
    sync_rates = {}
    update_list = []
    for IPport in nodes_value1.keys():
        if IPport in nodes_value2.keys():
            address, port = code_ip(IPport)
            height1 = nodes_value1[IPport][4]
            height2 = nodes_value2[IPport][4]
            blocksync_rate = round((height1-height2)/(ts1-ts2), 4)
            update_list.append("{}|{}".format(address, port))
            sync_rates["{}|{}".format(address, port)] = blocksync_rate

    print(sync_rates)
    nodes = session.query(Node).filter(
                and_(Node.date==datetime.datetime.now().strftime("%Y-%m-%d"),
                     func.concat_ws("|", Node.address, Node.port).in_(update_list))).with_for_update().all()
    session.bulk_update_mappings(Node, [{'id': x.id,'sync_rate': float(sync_rates["{}|{}".format(x.address, x.port)])} for x in nodes])
    session.commit()


if __name__ == "__main__":
    starttime = datetime.datetime.now()
    session = connect_db()
    calculate_syncrate(session)
    endtime = datetime.datetime.now()
    print('耗时：' + str((endtime - starttime).seconds) + 's')