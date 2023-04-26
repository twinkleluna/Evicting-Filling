# _*_ coding: utf-8 _*_
import re
import os
import pprint

def get_filelist(dir, list):
    newDir = dir
    if os.path.isfile(dir):
        list.append(dir)
        # # 若只是要返回文件文，使用这个
        # list.append(os.path.basename(dir))
    elif os.path.isdir(dir):
        for s in os.listdir(dir):
            # 如果需要忽略某些文件夹，使用以下代码
            # if s == "xxx":
            # continue
            newDir = os.path.join(dir, s)
            get_filelist(newDir, list)
    return list


def ipv4_mask(input_file):
    with open(input_file, 'r') as fr:
        try:
            data = fr.read()
        except:
            return
    ip_r = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]+)?)'
    re_ip = re.findall(ip_r, data)
    re_ip = [i[0] for i in re_ip]
    all_ip = list()
    for ri in re_ip:
        if ri not in all_ip:
            all_ip.append(ri)

    pprint.pprint(all_ip)

    ip_map = list()

    for i in range(len(all_ip)):
        key1, key2, key3, key4 = all_ip[i].split('.')
        item = '%s.%s.%s.*' % (key1, key2, key3)
        ip_map.append(item)
        # data = data.replace(all_ip[i], item)
        pattern = r'(\D)%s(\D)' % all_ip[i]
        repl = r'\g<1>%s\g<2>' % item
        data = re.sub(pattern, repl, data)

    with open(input_file, 'w') as fw:
        fw.write(data)


def ipv6_mask(input_file):
    with open(input_file, 'r') as fr:
        try:
            data = fr.read()
        except:
            return
    ipv6_r = r'([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7})'
    re_ipv6 = re.findall(ipv6_r, data)
    re_ipv6 = [i[0] for i in re_ipv6]
    all_ipv6 = list()
    for ri in re_ipv6:
        if ri not in all_ipv6:
            all_ipv6.append(ri)

    pprint.pprint(all_ipv6)

    ipv6_map = list()

    for i in range(len(all_ipv6)):
        try:
            key1, key2, key3, key4 = all_ipv6[i].split(':')[:4]
        except:
            print(all_ipv6[i])
            continue
        item = '%s:%s:%s:%s:*' % (key1, key2, key3, key4)
        ipv6_map.append(item)
        # data = data.replace(all_ip[i], item)
        pattern = r'(\D)%s(\D)' % all_ipv6[i]
        repl = r'\g<1>%s\g<2>' % item
        data = re.sub(pattern, repl, data)

    with open(input_file, 'w') as fw:
        fw.write(data)


if __name__ =='__main__' :
    filelist = get_filelist('./', [])
    print(len(filelist))
    for e in filelist:
        print(e)
        ipv4_mask(e)
        ipv6_mask(e)