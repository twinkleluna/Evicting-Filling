import pandas as pd
import numpy as np
import re

def generate():
    target_set = ['49.233.16.*:8333','[2402:4e00:1202:fe00:*]:8333',
                  '101.43.219.*:8333','101.43.219.*:8334',
                 '101.33.80.*:8333','dzm52lslwpm3qbjxmbftc4dbvk4in2eihbtoife6ybshxnzym2zwe2yd.onion:8333',
                 '43.132.198.*:8333','[240d:c000:2020:f00:*]:8333','qjrtbxjs3f5f2bw54yz4wvhvk2zlfodad5frifrnlltdzfistu2v5pqd.onion:8333',
                 'iybou5eoyg45ufbyrnrlif3ektrxej3b2v4v5wcyq6d7bugk3wj7smid.onion:8333','iv2zljzmqji7tytsksuprwj7ojp6uv67oq5uv6rymlcqjihpmz5xkmid.onion:8333',
                 'astsrlifm7bvjxsi4yampqfrlnf76efexa55l56rx4kzofewugbq26ad.onion:8333','keetg3aczdiegooddj7d6owxevdyd2vsgn2g7p6p6dvhabitdb3linid.onion:8333',
                  'pbtnuos6vsy4hqwq4ljyfvrtnbrayy62frlgooyv46sqafnu2sczugid.onion:8333','gjf6rkeopgbqmttguev2wb2yupv7t5eyfwtzdamncja34c5yhxrztpid.onion:8333',
                  'az6tz7n36wym4w46no4fxc5rmnnmirjqlamtuck5fqxiezyicmcarsqd.onion:8333','pzyzko2ipo5j6gyz46lftdojsqb7e7bgzlwcvmyksluyssiujole6kad.onion:8333',
                  '81.88.221.*:8333','109.173.41.*:8333',
                  '66.205.103.*:8333','205.201.123.*:8333',
                  'etmlnokcnfvmfk4yo2ggogaqkozu5nvdmgs4x25av6izssbbpsrfauid.onion:8333','4fykksxeeisvjkcwif76dbz7ac3en3m7yo246b22xvci56kdhj2ckwqd.onion:8333']
    list_a = []
    list_b = []
    for i in range(0, len(target_set)):
        for j in range(i+1,len(target_set)):
            list_a.append(target_set[i])
            list_b.append(target_set[j])
    output_excel = {'a': list_a, 'b': list_b}
    output = pd.DataFrame(output_excel)
    output['char_one'],output['char_two'],output['char_both'],output['target'] = np.nan,np.nan,np.nan,np.nan
    print(output)
    output = output.fillna(value=0)
    output.to_excel('result.xlsx', index=False)


def calculate():
    df = pd.read_excel('result.xlsx',engine='openpyxl')
    with open('result_correct.log','r') as f:
        for line in f.readlines():
            if "特征一：" in line:
                addr_a = "".join(re.findall(r'： [^ ]* ', line))[2:-1]
                addr_b = "".join(re.findall(re.escape(addr_a)+' [^ ]* ', line))[len(addr_a)+1:-1]
                flag = True if "True" in line else False
                index = df.loc[(df['a'] == addr_a) & (df['b'] == addr_b)].index
                df.loc[index,'char_one'] = flag
            elif "特征一+特征二：" in line:
                addr_a = "".join(re.findall(r'： [^ ]* ', line))[2:-1]
                addr_b = "".join(re.findall(re.escape(addr_a)+' [^ ]* ', line))[len(addr_a)+1:-1]
                flag = True if "True" in line else False
                index = df.loc[(df['a'] == addr_a) & (df['b'] == addr_b)].index
                df.loc[index,'char_both'] = flag
            elif "特征二：" in line:
                addr_a = "".join(re.findall(r'： [^ ]* ', line))[2:-1]
                addr_b = "".join(re.findall(re.escape(addr_a)+' [^ ]* ', line))[len(addr_a)+1:-1]
                flag = True if "True" in line else False
                index = df.loc[(df['a'] == addr_a) & (df['b'] == addr_b)].index
                df.loc[index,'char_two'] = flag
    df.to_excel('result.xlsx', index=False)


class Analysis():
    tp, fp, tn, fn = 0, 0, 0, 0
    def TT(self):
        self.tp += 1
    def TF(self):
        self.fp += 1
    def FF(self):
        self.tn += 1
    def FT(self):
        self.fn += 1
    def analysis_num(self, file, character):
        df = pd.read_excel(file, engine='openpyxl')
        for index,row in df.iterrows():
            fun_name = str(row['char_'+character])[0]+str(row['target'])[0]
            fun = getattr(self, fun_name)
            fun()
        return self.tp,self.fp,self.tn,self.fn
    def analysis_rate(self):
        tpr = self.tp / (self.tp + self.fn)
        fpr = self.fp/(self.fp+self.tn)
        tnr = self.tn / (self.tn + self.fp)
        fnr = self.fn / (self.fn + self.tp)
        return tpr,fpr,tnr,fnr
    def analysis_acc(self):
        acc = (self.tp+self.tn)/(self.tp+self.tn+self.fp+self.fn)
        p = self.tp/(self.tp+self.fp)
        r = self.tp/(self.tp+self.fn)
        return acc,p,r


if __name__ == "__main__":
    # generate()
    calculate()
    for i in ['one','two','both']:
        aly = Analysis()
        print(aly.analysis_num('result.xlsx', i))
        print(aly.analysis_rate())
        print(aly.analysis_acc())

