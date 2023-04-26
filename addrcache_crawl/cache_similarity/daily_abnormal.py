# -*- coding: utf-8 -*-
import json
import re
import html
import jieba
import jieba.analyse
from sklearn.metrics.pairwise import cosine_similarity
import json

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
    date = '2021-10-28'
    print("开始提取" + date + "abnormal cache data")

    abnormals = {}
    with open(filePath + date +'_hash_sim.log', 'r+') as f:
        hashes= json.loads(f.read())
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
    with open(filePath + date +'_collision.log', 'w+') as f:
        f.write(json.dumps(abnormals))