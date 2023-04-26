#!/usr/bin/python
# -*- coding: UTF-8 -*-
import matplotlib.pyplot as plt
from matplotlib.dates import date2num , DateFormatter
import datetime
import re
import time

def generate_data(file):
    times = []
    connections = []
    with open(file) as f:
        for line in f.readlines():
            if "there are" in line:
                connections.append(int("".join(re.findall(r'there are [^ ]*', line))[10:]))
                ts = "".join(re.findall(r'at[^.]*', line))[2:]
                # times.append(time.strftime("%H:%M:%S", time.localtime(int(ts))))
                times.append(datetime.datetime.fromtimestamp(int(ts)))
    date = time.strftime("%Y年%m月%d日", time.localtime(int(ts)))
    return date,times,connections


if __name__ == "__main__":
    # date,times,connections = generate_data('43.132.198.*_4.log')
    # date2,times2,connections2 = generate_data('240d:c000_4.log')
    date,times,connections = generate_data('tests/conn_pool/test/101.33.80.*:8333_1.log')
    date2,times2,connections2 = generate_data('tests/conn_pool/test/dzm52lslwpm3qbjxmbftc4dbvk4in2eihbtoife6ybshxnzym2zwe2yd.onion:8333_1.log')
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']
    fig, ax = plt.subplots()
    ax.plot_date(times, connections,'-', color='b',label='101.33.XX.XX:8333')
    ax.plot_date(times2, connections2, 'g--', label='dzm52lslwpXXX.onion:8333')
    ax.set_ylim(ymin=0)
    plt.vlines(times2[0], 0,connections[0], colors="r")
    ax.xaxis.set_major_formatter(DateFormatter('%H:%M:%S'))
    # plt.title("地址共享连接池实验("+date+")",size=15)
    plt.xlabel("time")  # 横坐标名字
    plt.ylabel("connections")  # 纵坐标名字
    ax.legend()
    plt.savefig('figures/行为特征说明图.png', dpi=300)
    plt.show()
