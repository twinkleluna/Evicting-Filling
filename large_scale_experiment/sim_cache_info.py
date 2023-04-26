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
from sklearn.metrics.pairwise import cosine_similarity

filePath = 'results/attackcost/0715/cache_info/'

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


class CosineSimilarity(object):
    """
    余弦相似度
    """
    def __init__(self, content_x1, content_x2):
        self.s1 = content_x1
        self.s2 = content_x2

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
        keywords = jieba.analyse.extract_tags("|".join(seg), topK=200, withWeight=False)
        return keywords

    @staticmethod
    def one_hot(word_dict, keywords):  # oneHot编码
        # cut_code = [word_dict[word] for word in keywords]
        cut_code = [0]*len(word_dict)
        for word in keywords:
            cut_code[word_dict[word]] += 1
        return cut_code

    def main(self):
        # 去除停用词
        jieba.analyse.set_stop_words('../cache_info/stopwords.txt')

        # 提取关键词
        keywords1 = self.extract_keyword(self.s1)
        keywords2 = self.extract_keyword(self.s2)
        # 词的并集
        union = set(keywords1).union(set(keywords2))
        # 编码
        word_dict = {
    }
        i = 0
        for word in union:
            word_dict[word] = i
            i += 1
        # oneHot编码
        s1_cut_code = self.one_hot(word_dict, keywords1)
        s2_cut_code = self.one_hot(word_dict, keywords2)
        # 余弦相似度计算
        sample = [s1_cut_code, s2_cut_code]
        # 除零处理
        try:
            sim = cosine_similarity(sample)
            return sim[1][0]
        except Exception as e:
            print(e)
            return 0.0


def calculateSimHash(start_date):
    targets = []
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
    add_hashes = {}
    for target in targets:
        with open(filePath + target, 'r+') as f:
            data = json.loads(f.read())
        for addr in data:
            content = data[addr]["new_addrs"]
            # list转化成str
            content = [str(x) for x in content]
            content = ''.join(content)[:1000]
            if content:
                num += 1
                sim_hash = SimHashSimilarity(content)
                sim_hash = sim_hash.main()
                add_hashes[addr] = [sim_hash, data[addr]["info"]["height"], data[addr]["info"]["version"],
                                    data[addr]["info"]["user_agent"], data[addr]["info"]["services"], content,
                                    data[addr]["rtt"] if "rtt" in data[addr] else 0]

    print("Start dumping")
    # with open(filePath + start_date +'_hash.log', 'w+') as f:
    #     f.write(json.dumps(hashes))
    with open(filePath + start_date +'_hash.log', 'w+') as f:
        f.write(json.dumps(add_hashes))
    print(num)


def cacheMapCollision(start_date, end_date):
    targets = []
    targets.append(start_date)
    next_date = (datetime.datetime.strptime(start_date, '%Y-%m-%d') + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    while next_date <= end_date:
        targets.append(next_date)
        next_date = (datetime.datetime.strptime(next_date, '%Y-%m-%d') + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    targets.sort(reverse=False)
    print(targets)

    with open("results/attackcost/0715/target_nodes.json", 'r+') as f:
        target_nodes = json.loads(f.read())

    hashes = {}
    for target in targets:
        with open(filePath + target + '_hash.log', 'r+') as f:
            add_hashes = json.loads(f.read())
        print(target)

    filtering_peers = []
    for i in range(0, len(target_nodes)):
        if i % 20 == 0:
            print("进度: " + str(i / len(target_nodes)))
        a = target_nodes[i]
        if a not in add_hashes:
            continue
        for j in range(i + 1, len(target_nodes)):
            b = target_nodes[j]
            if b not in add_hashes or [i, j] in filtering_peers:
                continue
            info_a, info_b = add_hashes[a], add_hashes[b]
            if info_a[0] == info_b[0]:
                similarity = CosineSimilarity(info_a[5],info_b[5])
                similarity = similarity.main()
                if similarity < 0.90:
                    filtering_peers.append([i, j])
            else:
                # print([i, j])
                filtering_peers.append([i, j])

    print("Start dumping")
    print("按照缓存信息初步过滤掉的地址对数为" + str(len(filtering_peers)))
    with open(filePath + 'filteringByCacheInfo.json', 'w+') as f3:
        f3.write(json.dumps(filtering_peers))


if __name__ == '__main__':
    calculateSimHash('2022-07-18')
    cacheMapCollision('2022-07-18', '2022-07-18')