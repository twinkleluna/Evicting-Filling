# -*- coding: utf-8 -*-
# 正则
import re
# html 包
import html
# 数学包
import math
# 自然语言处理包
import jieba
import jieba.analyse
import json


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
        print(keywords)
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
        jieba.analyse.set_stop_words('../cache_info/stopwords.txt')

        # 提取关键词
        s1 = self.extract_keyword(self.s1)

        sim_hash1 = self.run(s1)
        # print(f'相似哈希指纹1: {sim_hash1}\n相似哈希指纹2: {sim_hash2}')
        return sim_hash1


# 测试
if __name__ == '__main__':
    with open('../cache_info/hashes.log', 'r') as f:
        hashes = json.loads(f.read())

    with open('../cache_info/1635134077.log', 'r') as f:
        data = json.loads(f.read())

    #     with open('../cache_info/sample_x.txt', 'w+') as x:
    #         x.write(json.dumps(data["hhqkjligp4xkweow2lvbvjtkeehv4oldsrr2oaqzdu6bgmdvblbfgkid.onion:8333"]["new_addrs"]))
    #     with open('../cache_info/sample_y.txt', 'w+') as y:
    #         y.write(json.dumps(data["bk7yp6epnmcllq72.onion:8333"]["new_addrs"]))

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
            else:
                for i in hashes[sim_hash]:
                    if 'a' in hashes[sim_hash][i] and hashes[sim_hash][i]['a'] == addr \
                            and data[addr]["info"]["timestamp"]-hashes[sim_hash][i]['t'] < 21*60*60:
                        pass_flag = 1
                        break
            if not pass_flag:
                hashes[sim_hash].append({'a':addr, 't':data[addr]["info"]["timestamp"], 'n':content})

    with open('../cache_info/1635134077_hash.log', 'w+') as f:
        f.write(json.dumps(hashes))

    # with open('../cache_info/sample_x.txt', 'r') as x:
    #     content_x = x.read(1000)
    # with open('../cache_info/sample_y.txt', 'r') as y:
    #     content_y = y.read(1000)
    #
    # sim_hash = SimHashSimilarity(content_x)
    # sim_hash1 = sim_hash.main()
    #
    # sim_hash2 = SimHashSimilarity(content_y)
    # sim_hash2 = sim_hash2.main()
    # print(sim_hash1)
    # print(sim_hash2)
    # length = 0
    # # for addr in hashes:
    # #     hashes[addr]
    # for index, char in enumerate(sim_hash1):
    #     if char == sim_hash2[index]:
    #         continue
    #     else:
    #         length += 1
    #
    # # 阀值
    # threshold = 1
    # print(f'海明距离：{length} 判定距离：{threshold} 是否相似：{length <= threshold}')
