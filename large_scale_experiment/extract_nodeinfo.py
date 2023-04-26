import re
from datetime import date, datetime
import json

class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return json.JSONEncoder.default(self, obj)


def deduplicate_log():
    readDir = "debug.log"
    writeDir = "filter_debug.log"
    lines_seen = set()
    outfile = open(writeDir, "w")
    print(readDir)
    f = open(readDir, "r")
    for line in f:
        if line not in lines_seen:
            outfile.write(line)
            lines_seen.add(line)
    outfile.close()

def bitnodes_code_ip(inp):
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

if __name__ == '__main__':
    lines_seen = set()
    addrs_info = {}

    with open("peerids") as f:
        peerids = json.loads(f.read())

    with open("/root/nodeinfo-22.0/10573968479/debugas") as f:
        for line in f.readlines():
            start_timestamp = "2022-05-09T03:20:04Z"
            end_timestamp = "2022-05-09T03:26:53Z"
            if not line[:20].startswith('2022') or line[:20] < start_timestamp:
                continue
            if line[:20] > end_timestamp:
                break
            if line not in lines_seen:
                lines_seen.add(line)
            else:
                continue
            ts = "".join(re.findall(r'[^ ]* HEADERS: peer=', line))[:-15]
            if ts == "":
                continue
            timestamp = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
            peerid = "".join(re.findall(r'peer=[^,]*', line))[5:]
            host = "".join(re.findall(r'peeraddr=[^,]*', line))[9:]
            # address, port = bitnodes_code_ip(host)
            version = "".join(re.findall(r'version: [^,]*', line))[9:]
            user_agent = "".join(re.findall(r'_agent:[^,]*', line))[7:]
            services = int("".join(re.findall(r'sevices:[^,]*', line))[8:])
            last_height = int("".join(re.findall(r'vRecv\):[^$]*', line))[7:])
            if '{}|{}'.format(peerid,host) not in peerids:
                peerids['{}|{}'.format(peerid,host)] = last_height
                addrs_info[host] = {'version': version, 'user_agent': user_agent, 'services': services, 'height_seq': {}}
            elif host not in addrs_info and last_height!=peerids['{}|{}'.format(peerid,host)]:
                addrs_info[host] = {'version': version,'user_agent': user_agent,'services': services,'height_seq':{last_height:timestamp}}
            elif last_height !=1 and last_height!=peerids['{}|{}'.format(peerid,host)] and last_height not in addrs_info[host]['height_seq']:
                addrs_info[host]['height_seq'][last_height] = timestamp
            # elif last_height == 1:
            #     addrs_info[host]['height_seq'][max(addrs_info[host]['height_seq'], key=addrs_info[host]['height_seq'].get)+1] = timestamp

    print(len(addrs_info))
    with open("peerids",'w+') as f:
        f.write(json.dumps(peerids))
    with open("extracted/"+start_timestamp+"-"+end_timestamp, 'w+') as f:
        f.write(json.dumps(addrs_info,cls=ComplexEncoder))
