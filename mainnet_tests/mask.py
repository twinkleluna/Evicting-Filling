# _*_ coding: utf-8 _*_
import re
import os
import pprint
import pandas as pd

def get_filelist(dir, list):
    # newDir = dir
    # if os.path.isfile(dir):
    #     list.append(dir)
    #     # list.append(os.path.basename(dir))
    # elif os.path.isdir(dir):
    #     for s in os.listdir(dir):
    #         newDir = os.path.join(dir, s)
    #         get_filelist(newDir, list)
    tmp = os.listdir(dir)
    for line in tmp:
        filepath = os.path.join(dir, line)
        if os.path.isfile(filepath):
            list.append(filepath)
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
        # data = data.replace(all_ipv6[i], item)
        pattern = r'(\D)%s(\D)' % all_ipv6[i]
        repl = r'\g<1>%s\g<2>' % item
        data = re.sub(pattern, repl, data)

    with open(input_file, 'w') as fw:
        fw.write(data)


def parse_data(file_path):
    """替换 Excel 特殊字符"""
    try:
        df = pd.read_excel(file_path)
    except:
        raise "数据读取异常"
    # 遍历每个单元格, 先行后列
    row, col = df.shape
    for i in range(row):
        for j in range(col):
            # 当前格元素, 发现上面写不对, 字符校验应该在这里
            cur_value = str(df.iloc[i, j])
            pure_char = cur_value
            # print(cur_value)
            ip_r = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]+)?)'
            re_ip = re.findall(ip_r, cur_value)
            for q in re_ip:
                ip = q[0]
                key1, key2, key3, key4 = ip.split('.')
                item = '%s.%s.%s.*' % (key1, key2, key3)
                pure_char = pure_char.replace(ip, item)

            ipv6_r = r'([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7})'
            re_ipv6 = re.findall(ipv6_r, pure_char)
            for q in re_ipv6:
                ipv6 = q[0]
                try:
                    key1, key2, key3, key4 = ipv6[i].split(':')[:4]
                except:
                    continue
                item = '%s:%s:%s:%s:*' % (key1, key2, key3, key4)
                pure_char = pure_char.replace(ipv6, item)
            # pure_char = replace_char(cur_value, replace_char)
            # 把特殊字符, 及其所在的行列坐标给打印出来
            if str(cur_value) != pure_char:
                df.iloc[i, j] = pure_char
                print(cur_value)

    df.to_excel(file_path, index=False)


if __name__ =='__main__' :
    filelist = get_filelist('./', [])
    print(len(filelist))
    for e in filelist:
        print(e)
        if(e[-4:]=='xlsx'):
            parse_data(e)
        else:
            ipv4_mask(e)
            ipv6_mask(e)