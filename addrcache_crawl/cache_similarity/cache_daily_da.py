# -*- coding: utf-8 -*-
import re
import html
import math
import jieba
import jieba.analyse
import json
import os
import datetime
import time

filePath = '/home/ubuntu/opennodes/cache_info/'

class SimHashSimilarity(object):
    """
    SimHash
    """
    def __init__(self, content_x):
        self.s1 = content_x

    @staticmethod
    def get_bin_str(source):  # 字符串转二进制
        if source == "":
            return 0
        else:
            t = ord(source[0]) << 7
            m = 1000003
            mask = 2 ** 128 - 1
            for c in source:
                t = ((t * m) ^ ord(c)) & mask
            t ^= len(source)
            if t == -1:
                t = -2
            t = bin(t).replace('0b', '').zfill(64)[-64:]
            return str(t)

    @staticmethod
    def extract_keyword(content):  # 提取关键词
        # 正则过滤 html 标签
        re_exp = re.compile(r'(<style>.*?</style>)|(<[^>]+>)', re.S)
        content = re_exp.sub(' ', content)
        # html 转义符实体化
        content = html.unescape(content)
        # 切割
        seg = [i for i in jieba.cut(content, cut_all=True) if i != '']
        # 提取关键词
        keywords = jieba.analyse.extract_tags("|".join(seg), topK=200, withWeight=True)
        return keywords

    def run(self, keywords):
        ret = []
        for keyword, weight in keywords:
            bin_str = self.get_bin_str(keyword)
            key_list = []
            for c in bin_str:
                weight = math.ceil(weight)
                if c == "1":
                    key_list.append(int(weight))
                else:
                    key_list.append(-int(weight))
            ret.append(key_list)
        # 对列表进行"降维"
        rows = len(ret)
        cols = len(ret[0])
        result = []
        for i in range(cols):
            tmp = 0
            for j in range(rows):
                tmp += int(ret[j][i])
            if tmp > 0:
                tmp = "1"
            elif tmp <= 0:
                tmp = "0"
            result.append(tmp)
        return "".join(result)

    def main(self):
        # 去除停用词
        jieba.analyse.set_stop_words(filePath+'stopwords.txt')

        # 提取关键词
        s1 = self.extract_keyword(self.s1)

        sim_hash1 = self.run(s1)
        # print(f'相似哈希指纹1: {sim_hash1}\n相似哈希指纹2: {sim_hash2}')
        return sim_hash1


if __name__ == '__main__':
    targets = []
    # 从文件中读取timestamp，往后计算
    with open(filePath + 'last_calculate.log', 'r') as f2:
        start_date = f2.read(10)
        start_timestamp = int(time.mktime(datetime.datetime.strptime(start_date, "%Y-%m-%d").timetuple()))-600
        end_timestamp = start_timestamp+3600*24

    for i, j, k in os.walk(filePath):
        for log in k:
            if 'c' in log or 'txt' in log or 'hash' in log or int(log[:10]) <= start_timestamp \
                    or int(log[:10]) >= end_timestamp:
                continue
            else:
                targets.append(log)
    print("开始提取" + start_date + " cache data")
    targets.sort(reverse=False)
    print(targets)

    num = 0
    hashes = {}
    simple_hashes = {}
    for target in targets:
        with open(filePath + target, 'r+') as f:
            data = json.loads(f.read())
        for addr in data:
            content = data[addr]["new_addrs"]
            # list转化成str
            content = [str(x) for x in content]
            content = ''.join(content)[:1000]
            if content:
                sim_hash = SimHashSimilarity(content)
                sim_hash = sim_hash.main()
                pass_flag = 0
                if not sim_hash in hashes:
                    hashes[sim_hash] = []
                    simple_hashes[sim_hash] = []
                else:
                    for i in range(len(hashes[sim_hash])):
                        if 'a' in hashes[sim_hash][i] and hashes[sim_hash][i]['a'] == addr \
                            and data[addr]["info"]["timestamp"]-hashes[sim_hash][i]['t'] < 27*60*60:
                            pass_flag = 1
                            break
                if not pass_flag:
                    num += 1
                    hashes[sim_hash].append({'a':addr, 't':data[addr]["info"]["timestamp"],'height': data[addr]["info"]["height"],
                                             'version': data[addr]["info"]["version"], 'user_agent': data[addr]["info"]["user_agent"],
                                             'services': data[addr]["info"]["services"], 'n':data[addr]["new_addrs"],
                                             'rtt':data[addr]["rtt"] if "rtt" in data[addr] else 0})
                    simple_hashes[sim_hash].append({'a':addr, 't':data[addr]["info"]["timestamp"],'height': data[addr]["info"]["height"],
                                             'version': data[addr]["info"]["version"], 'user_agent': data[addr]["info"]["user_agent"],
                                             'services': data[addr]["info"]["services"], 'n':content,
                                             'rtt':data[addr]["rtt"] if "rtt" in data[addr] else 0})

    print("Start dumping")
    with open(filePath + start_date +'_hash.log', 'w+') as f:
        f.write(json.dumps(hashes))
    with open(filePath + start_date +'_hash_sim.log', 'w+') as f:
        f.write(json.dumps(simple_hashes))

    with open(filePath + 'last_calculate.log', 'w+') as f3:
        f3.write(datetime.datetime.fromtimestamp(end_timestamp).strftime("%Y-%m-%d"))

    print(num)
