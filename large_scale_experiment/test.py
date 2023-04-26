import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import date, datetime
from itertools import groupby

def show_overlapping_part():
    with open("test.txt") as f:
        ids = json.loads(f.read())
    seq_a = ids["a"]
    seq_b = ids["b"]

    print(len(seq_a))
    print(len(seq_b))
    for i in seq_a:
        if i in seq_b:
            print(i)
            print(seq_a[i], seq_b[i])


def get_time_seconds(start_time, end_time):
    start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
    end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    start_end_time_seconds = (end_time - start_time).total_seconds()  # 时间差的计算，单位为秒，这个是正确的计算方法
    return abs(int(start_end_time_seconds))


def get_overlapping_time(seq_a,seq_b):
    tmp = []
    for i in seq_a:
        if i in seq_b:
            tmp.append(get_time_seconds(seq_a[i], seq_b[i]))
    return tmp


def get_multiaddrs_sync(target_addrs):
    # target_addrs = [['a7n3hcltl4jhy6uvoh4lnkk6ti5tlnsm52icv6yjxd722z5cc5asq5qd.onion:8333','[2a00:d880:5:c2:*d329]:8333'],
    #                 ['vq65zxv5pdjoe6bimwfo3il3e3ukbnoan7mpi3khm56fbrawmj3kwsad.onion:8333','neocrypt3kwgk3pqhksd4tlkvict45kfpjc34fhbzjvgs4dlquxyldyd.onion:8333'],
    #                 ['193.32.127.*:60969','193.32.127.*:60969','193.32.127.*:60969'],
    #                 ['217.138.199.*:56805','217.138.199.*:56805','217.138.199.*:56805'],
    #                 ['109.173.41.*:8333','77.37.212.*:8333'],
    #                 ['[2604:7c00:120:4b:*eb24]:8333','195.123.239.*:8333','104.129.171.*:8333'],
    #                 ['95.56.65.*:18333','84.252.157.*:18333'],
    #                 ['a7n3hcltl4jhy6uvoh4lnkk6ti5tlnsm52icv6yjxd722z5cc5asq5qd.onion:8333','[2a00:d880:5:c2:*d329]:8333','81.4.100.*:8333'],
    #                 ['109.173.41.*:8333','81.88.221.*:8333'],
    #                 ]
    overlapping_time = []

    with open("/Users/yanghuashuang/results_bk_first_no_tolerance/addrs_info.txt", 'r') as f:
        addrs_info = json.loads(f.read())

    for pairs in target_addrs:
        for i in range(0,len(pairs)):
            for j in range(i+1,len(pairs)):
                overlapping_time += get_overlapping_time(addrs_info[pairs[i]]["height_seq"],addrs_info[pairs[j]]["height_seq"])

    print(len(overlapping_time))
    print(np.mean(overlapping_time))
    print(np.var(overlapping_time))

    dic = []
    intervals = {'{0}-{1}'.format(5 * x + 1, 5 * (x + 1)): 0 for x in range(20)}
    for _ in overlapping_time:
        for interval in intervals:
            start, end = tuple(interval.split('-'))
            if int(start) <= _ <= int(end):
                dic.append(interval)
    # print(dic)

    overlapping_time = pd.value_counts(dic,normalize=True)
    overlapping_time.sort_index(inplace=True)
    for i in range(overlapping_time.size):
        if type(overlapping_time.iloc[i]) == np.float64:
            overlapping_time.iloc[i] = overlapping_time.iloc[i] * 100
        else:
            pass
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']
    y_ticks = range(110)
    plt.yticks(y_ticks[::10])
    plt.ylim((min(overlapping_time.values), 100))
    plt.plot(list(overlapping_time.index), list(overlapping_time.values), c='black', linewidth=0.4)
    # plt.scatter(list(overlapping_time.size.index), list(overlapping_time.size.values), c='black',s=10.0)
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.show()


def get_normal_sync():
    overlapping_time = []

    with open("/Users/yanghuashuang/results_bk_first_no_tolerance/addrs_info.txt", 'r') as f:
        addrs_info = json.loads(f.read())
    addrs_list = list(addrs_info.keys())

    for i in range(0, 160):
        i = i*25
        for j in range(i + 1, i + 5):
            overlapping_time += get_overlapping_time(addrs_info[addrs_list[i]]["height_seq"],addrs_info[addrs_list[j]]["height_seq"])

    print(len(overlapping_time))
    print(np.mean(overlapping_time))
    print(np.var(overlapping_time))

    dic = []
    intervals = {'{0}-{1}'.format(5 * x + 1, 5 * (x + 1)): 0 for x in range(20)}
    for _ in overlapping_time:
        for interval in intervals:
            start, end = tuple(interval.split('-'))
            if int(start) <= _ <= int(end):
                dic.append(interval)
    # print(dic)

    overlapping_time = pd.value_counts(dic,normalize=True)
    overlapping_time.sort_index(inplace=True)
    for i in range(overlapping_time.size):
        if type(overlapping_time.iloc[i]) == np.float64:
            overlapping_time.iloc[i] = overlapping_time.iloc[i] * 100
        else:
            pass
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']
    y_ticks = range(110)
    plt.yticks(y_ticks[::10])
    plt.ylim((min(overlapping_time.values), 100))
    plt.plot(list(overlapping_time.index), list(overlapping_time.values), c='black', linewidth=0.4)
    # plt.scatter(list(overlapping_time.size.index), list(overlapping_time.size.values), c='black',s=10.0)
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.show()


if __name__ == '__main__':
    target_addrs = [['[2604:7c00:120:4b:*eb24]:8333','195.123.239.*:8333'],
                    ['[2604:7c00:120:4b:*eb24]:8333','104.129.171.*:8333'],
                    ['[2a00:d880:5:c2:*d329]:8333','81.4.100.*:8333'],
                    ]
    get_multiaddrs_sync(target_addrs)
    # get_normal_sync()




