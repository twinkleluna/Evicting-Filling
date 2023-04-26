from datetime import date, datetime
import json
import pandas as pd
import os
from collections import Counter
import numpy as np
import matplotlib.pyplot as plt
import csv


class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return json.JSONEncoder.default(self, obj)


def get_time_seconds(start_time, end_time):
    start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
    end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    start_end_time_seconds = (end_time - start_time).total_seconds()  # 时间差的计算，单位为秒，这个是正确的计算方法
    return abs(int(start_end_time_seconds))


def summary_info():
    path = 'extracted/'
    files = os.listdir(path)  # files是一个列表
    addrs_info = {}
    for file in files:
        f = open(path+file, "r")
        info = json.loads(f.read())
        for addr in info:
            if addr not in addrs_info:
                addrs_info[addr] = info[addr]
            else:
                for i in info[addr]['height_seq']:
                    if i not in addrs_info[addr]['height_seq']:
                        addrs_info[addr]['height_seq'][i] = info[addr]['height_seq'][i]
    print(len(addrs_info))
    with open('results/addrs_info.txt','w+') as f:
        f.write(json.dumps(addrs_info))




def compare_results():
    # with open("results/clear_addrs_info.txt", 'r') as f:
    with open("/Users/yanghuashuang/results_bk_first_no_tolerance/addrs_info.txt", 'r') as f:
        addrs_info = json.loads(f.read())
    addrs_list = list(addrs_info.keys())
    results = {}
    success_overlapping_ana = []

    for addr in range(0,len(addrs_list)):
        for item in range(addr+1,len(addrs_list)):
            # print(addrs_list[addr],addrs_list[item])
            if addrs_info[addrs_list[addr]]['version']==addrs_info[addrs_list[item]]['version'] and \
                    addrs_info[addrs_list[addr]]['user_agent']==addrs_info[addrs_list[item]]['user_agent'] \
                    and addrs_info[addrs_list[addr]]['services']==addrs_info[addrs_list[item]]['services']:
                tag = True
            else:
                continue
            false_tol = 0
            success_num = 0
            for i in addrs_info[addrs_list[addr]]['height_seq']:
                if i in addrs_info[addrs_list[item]]['height_seq'] and get_time_seconds(addrs_info[addrs_list[addr]]['height_seq'][i],addrs_info[addrs_list[item]]['height_seq'][i])>2:
                    false_tol += 1
                if i in addrs_info[addrs_list[item]]['height_seq'] and get_time_seconds(addrs_info[addrs_list[addr]]['height_seq'][i],addrs_info[addrs_list[item]]['height_seq'][i]) <= 2:
                    success_num += 1

                for j in range(int(i)+1,int(i)+2):
                    if str(j) in addrs_info[addrs_list[item]]['height_seq'] and addrs_info[addrs_list[addr]]['height_seq'][i]>=addrs_info[addrs_list[item]]['height_seq'][str(j)]:
                        tag = False
                        break
                if false_tol > 2:
                    tag = False
                if not tag:
                    break
            if success_num >= 300 and tag:
                if addrs_list[addr] in results:
                    results[addrs_list[addr]].add(addrs_list[item])
                else:
                    results[addrs_list[addr]] = {addrs_list[item]}
                success_overlapping_ana.append(success_num)
    pd.DataFrame.from_dict(data=results, orient='index').to_csv('results/test_ov_more_200.csv', header=False)
    print(len(addrs_info))

    with open('results/success_overlapping_ana.txt','w+') as f:
        f.write(json.dumps(success_overlapping_ana))
    print(len(success_overlapping_ana))
    print(np.mean(success_overlapping_ana))
    print(np.var(success_overlapping_ana))

    dic = []
    intervals = {'{0}-{1}'.format(5 * x + 1, 5 * (x + 1)): 0 for x in range(20)}
    for _ in success_overlapping_ana:
        for interval in intervals:
            start, end = tuple(interval.split('-'))
            if int(start) <= _ <= int(end):
                dic.append(interval)
    # print(dic)

    success_overlapping_ana = pd.value_counts(dic, normalize=True)
    success_overlapping_ana.sort_index(inplace=True)
    for i in range(success_overlapping_ana.size):
        if type(success_overlapping_ana.iloc[i]) == np.float64:
            success_overlapping_ana.iloc[i] = success_overlapping_ana.iloc[i] * 100
        else:
            pass
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']
    y_ticks = range(110)
    plt.yticks(y_ticks[::10])
    plt.ylim((min(success_overlapping_ana.values), 100))
    plt.plot(list(success_overlapping_ana.index), list(success_overlapping_ana.values), c='black', linewidth=0.4)
    # plt.scatter(list(overlapping_time.size.index), list(overlapping_time.size.values), c='black',s=10.0)
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.show()


def analysis_lens():
    with open("results/addrs_info.txt", 'r') as f:
        addrs_info = json.loads(f.read())
    lens = []
    for addr in addrs_info:
        lens.append(len(addrs_info[addr]['height_seq']))
    result = Counter(lens)
    print(result)


def cut_short_lens():
    with open("results/addrs_info.txt", 'r') as f:
        addrs_info = json.loads(f.read())
    clear_addrs_info = {}
    for addr in addrs_info:
        if len(addrs_info[addr]['height_seq']) < 50:
            continue
        clear_addrs_info[addr] = addrs_info[addr]
    with open("results/clear_addrs_info.txt", 'w+') as f:
        f.write(json.dumps(clear_addrs_info))


def tmp():
    with open('results/success_overlapping_ana.txt','r') as f:
        success_overlapping_ana = json.loads(f.read())
    print(len(success_overlapping_ana))
    print(np.mean(success_overlapping_ana))
    print(np.var(success_overlapping_ana))

    dic = []
    intervals = {'{0}-{1}'.format(100 * x + 1, 100 * (x + 1)): 0 for x in range(10)}
    for _ in success_overlapping_ana:
        for interval in intervals:
            start, end = tuple(interval.split('-'))
            if int(start) <= _ <= int(end):
                dic.append(interval)
    # print(dic)

    success_overlapping_ana = pd.value_counts(dic, normalize=True)
    success_overlapping_ana.sort_index(inplace=True)
    for i in range(success_overlapping_ana.size):
        if type(success_overlapping_ana.iloc[i]) == np.float64:
            success_overlapping_ana.iloc[i] = success_overlapping_ana.iloc[i] * 100
        else:
            pass
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']
    y_ticks = range(110)
    plt.yticks(y_ticks[::10])
    plt.ylim((min(success_overlapping_ana.values), 100))
    plt.plot(list(success_overlapping_ana.index), list(success_overlapping_ana.values), c='black', linewidth=0.4)
    # plt.scatter(list(overlapping_time.size.index), list(overlapping_time.size.values), c='black',s=10.0)
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.show()


def online_time_filter():
    compare_results = {}
    with open('/Users/yanghuashuang/results_bk_first_no_tolerance/test_70.csv', 'r') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            compare_results[row[0]] = [row[i] for i in range(1,len(row))]

    with open("/Users/yanghuashuang/opennodes/node_online_stats/summary_stats_2.json", 'r') as f:
        online_data = json.loads(f.read())

    results = {}
    for key in compare_results:
        results[key] = []
        for value in range(0,len(compare_results[key])):
            # online_data[i] = [first_seen,last_seen,last_seen-first_seen,difftime]
            if compare_results[key][value] == '' or key not in online_data or compare_results[key][value] not in online_data:
                continue
            if online_data[key][0]>online_data[compare_results[key][value]][1] or online_data[key][1]<online_data[compare_results[key][value]][0]:
                continue
            else:
                results[key].append(value)
    pd.DataFrame.from_dict(data=results, orient='index').to_csv('results/compare/test_70.csv', header=False)
    print("OVER")


def pending_pairs_count():
    count = 0
    with open('results/test_ov_more_200.csv', 'r') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            for i in range(1, len(row)):
                if row[i] != '':
                    count += 1
    print(count)


if __name__ == '__main__':
    # with open("extracted/2022-05-05T11:20:00Z-2022-05-05T13:20:00Z", 'r') as f:
    #     addrs_info = json.loads(f.read())
    # summary_info()
    # analysis_lens()
    # cut_short_lens()
    # compare_results()

    # online_time_filter()
    pending_pairs_count()

    # with open('/Users/yanghuashuang/results_bk_first_no_tolerance/clear_addrs_info.txt', 'r') as f:
    #     addrs_info = json.loads(f.read())
    # print(len(addrs_info))



