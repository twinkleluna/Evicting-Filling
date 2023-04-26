# -*- coding: utf-8 -*-
import json
import re
import html
import jieba
import jieba.analyse
from sklearn.metrics.pairwise import cosine_similarity
import json
import os
import datetime
import numpy as np
import pandas as pd

filePath = '/home/ubuntu/opennodes/cache_info/'

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


if __name__ == '__main__':
    start_date = '2021-10-28'
    end_date = '2021-11-04'
    print("开始提取 " + start_date + "~"+ end_date + " abnormal cache data")

    targets = []
    targets.append(start_date)
    next_date = (datetime.datetime.strptime(start_date, '%Y-%m-%d') + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    while next_date <= end_date:
        targets.append(next_date)
        next_date = (datetime.datetime.strptime(next_date, '%Y-%m-%d') + datetime.timedelta(days=1)).strftime("%Y-%m-%d")

    targets.sort(reverse=False)
    print(targets)

    hashes = {}
    for target in targets:
        with open(filePath + target +'_hash_sim.log', 'r+') as f:
            new_hashes = json.loads(f.read())
            f.close()
        print(target)
        for new_hash in new_hashes:
            if not new_hash in hashes:
                hashes[new_hash] = []
                for i in range(len(new_hashes[new_hash])):
                    hashes[new_hash].append(new_hashes[new_hash][i])
            else:
                for i in  range(len(new_hashes[new_hash])):
                    pass_flag = 0
                    for j in range(len(hashes[new_hash])):
                        if new_hashes[new_hash][i]['a'] == hashes[new_hash][j]['a'] \
                            and new_hashes[new_hash][i]['t']-hashes[new_hash][j]['t'] < 27*60*60:
                            pass_flag = 1
                            break
                    if not pass_flag:
                        hashes[new_hash].append(new_hashes[new_hash][i])

    print("Start dumping historical hashes")
    with open(filePath + 'history_hash.log', 'w+') as f2:
        f2.write(json.dumps(hashes))

    abnormals = {}
    for sim_hash in hashes:
        if len(hashes[sim_hash]) > 1:
            abnormals[sim_hash] = []

    for sim_hash in abnormals:
        already = []
        #两两进行比对，存在相同的就插入abnormals
        for i in range(len(hashes[sim_hash])):
            if len(hashes[sim_hash])>= i+1:
                for j in range(i+1,len(hashes[sim_hash])):
                    similarity = CosineSimilarity(hashes[sim_hash][i]['n'],hashes[sim_hash][j]['n'])
                    similarity = similarity.main()
                    if similarity > 0.90:
                        if not i in already:
                            abnormals[sim_hash].append(hashes[sim_hash][i])
                            already.append(i)
                        if not j in already:
                            abnormals[sim_hash].append(hashes[sim_hash][j])
                            already.append(j)

    print("Start dumping")
    with open(filePath + 'history_collision.log', 'w+') as f3:
        f3.write(json.dumps(abnormals))

    abnormals_excel = {}
    for sim_hash in abnormals:
        if len(abnormals[sim_hash])>1:
            for i in range(len(abnormals[sim_hash])):
                abnormals_excel[abnormals[sim_hash][i]['a']+"|"+str(abnormals[sim_hash][i]['t'])]=\
                    [abnormals[sim_hash][i]['a'],abnormals[sim_hash][i]['t'],abnormals[sim_hash][i]["height"],abnormals[sim_hash][i]["version"],
                     abnormals[sim_hash][i]["user_agent"],abnormals[sim_hash][i]["services"],abnormals[sim_hash][i]["rtt"],
                     abnormals[sim_hash][i]['n'],
                     sim_hash, False]
            already = []
            for i in range(len(abnormals[sim_hash])):
                if len(abnormals[sim_hash]) >= i+1:
                    for j in range(i+1, len(abnormals[sim_hash])):
                        if abnormals[sim_hash][i]["services"]==abnormals[sim_hash][j]["services"] \
                                and abnormals[sim_hash][i]["version"]==abnormals[sim_hash][j]["version"] \
                                and abnormals[sim_hash][i]["user_agent"]==abnormals[sim_hash][j]["user_agent"] \
                                and abs(abnormals[sim_hash][i]["height"]-abnormals[sim_hash][j]["height"])<=abs(abnormals[sim_hash][i]["t"]-abnormals[sim_hash][j]["t"])/600+12:
                            if not i in already:
                                abnormals_excel[abnormals[sim_hash][i]['a']+"|"+str(abnormals[sim_hash][i]['t'])][-1] = True
                                already.append(i)
                            if not j in already:
                                abnormals_excel[abnormals[sim_hash][j]['a']+"|"+str(abnormals[sim_hash][j]['t'])][-1] = True
                                already.append(j)

    df = pd.DataFrame(abnormals_excel).T
    df.to_excel(filePath + 'history_collision_normal.xlsx')

    # with open(filePath + 'history_collision_easy.log', 'w+') as f4:
    #     f4.write(json.dumps(abnormals_easy))