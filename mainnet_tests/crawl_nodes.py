import requests
import json
import re
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Node,Base
import datetime

root_path = '~/Evicting-filling\ attack/mainnet_tests/'

def connect_db():
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://***:******@*.*.*.*:3306/idbitnodes'
    engine = create_engine(SQLALCHEMY_DATABASE_URI, echo=False)
    Base.metadata.create_all(engine)
    Sess = sessionmaker(bind=engine, autoflush=False)
    return Sess()

def code_ip(inp):
    if ".onion" in inp:
        address = "".join(re.findall( r'[^ ]*:', inp))[:-1]
        port = "".join(re.findall( r':[^ ]*', inp))[1:]
    elif "." in inp:
        address = "".join(re.findall(r'[^ ]*:', inp))[:-1]
        port = "".join(re.findall(r':[^ ]*', inp))[1:]
    elif ":" in inp:
        #IPv6
        address = "".join(re.findall(r'[^ ]*]', inp))[1:-1]
        port = "".join(re.findall(r'][^ ]*', inp))[2:]
    return address,port

def catch_nodes():
    url = "https://bitnodes.io/api/v1/snapshots/latest/"
    try:
        res = requests.get(url)
    except requests.exceptions.ProxyError or requests.exceptions.ConnectionError:
        print("anything wrong with api requests")
        return
    json_str = json.loads(res.text)
    # Beijing 时间
    with open(root_path+'nodes_info/'+str(datetime.datetime.now().strftime('%Y%m%d%H'))+'.txt','w+') as f:
        f.write(json.dumps(json_str))
    nodes_value = json_str.get("nodes")
    timestamp = json_str.get("timestamp")
    date = time.strftime("%Y-%m-%d", time.localtime(int(json_str.get("timestamp"))))
    nodes = {}
    for IPport in nodes_value.keys():
        if not "Satoshi:22.0.0" in nodes_value[IPport][1]:
            continue
        address, port = code_ip(IPport)
        version = nodes_value[IPport][0]
        user_agent = nodes_value[IPport][1]
        services = nodes_value[IPport][3]
        height = nodes_value[IPport][4]
        key = address + "|" + str(port)
        if key not in nodes:
            nodes[key]=(address, port, date, 0, timestamp, height, version, user_agent, services,0,'','','',0,'','')
    return nodes,date

def dedup_nodes(nodes,session,date):
    node_addresses = {"{}|{}".format(y.address, y.port) for y in
                               session.query(Node.address, Node.port).filter(Node.date == date).all()}
    for key in nodes:
        if not key in node_addresses:
            #生成newNode->session.add()进数据库，同时node_addresses[network].add()
            node_addresses.add(key)
            newNode = Node(address=nodes[key][0], port=int(nodes[key][1]), date=nodes[key][2],
                    seen = nodes[key][3],timestamp=int(nodes[key][4]),height=int(nodes[key][5]),version=int(nodes[key][6]),user_agent=nodes[key][7],
                    services=int(nodes[key][8]) if nodes[key][8]!=None else 0, w_tried=int(nodes[key][9]),
                    os=nodes[key][10], wfp=nodes[key][11],afp=nodes[key][12], sync_rate=nodes[key][13], same=nodes[key][14],filter=nodes[key][15])
            session.add(newNode)
    session.commit()


if __name__ == '__main__':
    print("start collect nodes...")
    starttime = datetime.datetime.now()
    session = connect_db()
    try:
        nodes,date = catch_nodes()
        dedup_nodes(nodes,session,date)
        print("end successfully!!!")
    except Exception as e:
        print(e)
    endtime = datetime.datetime.now()
    print('耗时：' + str((endtime - starttime).seconds) + 's')