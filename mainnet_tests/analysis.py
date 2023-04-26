import json
import time
import re
import pandas as pd
import matplotlib.pyplot as plt
from sqlalchemy import create_engine,and_,or_
from sqlalchemy.orm import sessionmaker
from models import Node,Base
from datetime import date, datetime
import numpy as np
import os
import math

from matplotlib import rcParams

config = {
"font.family": 'serif', # 衬线字体
"font.size": 10, # 相当于小四大小
# "font.serif": ['Songti SC'], # 宋体
"font.serif": ['Linux Libertine'],
# "mathtext.fontset": 'stix', # matplotlib渲染数学字体时使用的字体，和Times New Roman差别不大
'axes.unicode_minus': False # 处理负号，即-号
}
rcParams.update(config)

def connect_db():
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://***:******@*.*.*.*:3306/idbitnodes'
    engine = create_engine(SQLALCHEMY_DATABASE_URI, echo=False)
    Base.metadata.create_all(engine)
    Sess = sessionmaker(bind=engine, autoflush=False)
    return Sess()


def code_ip(inp):
    if ".onion" in inp:
        address = "".join(re.findall( r'[^ ]*:', inp))[:-1]
        port = "".join(re.findall( r':[^ ]*', inp))[1:]
    elif "." in inp:
        address = "".join(re.findall(r'[^ ]*:', inp))[:-1]
        port = "".join(re.findall(r':[^ ]*', inp))[1:]
    elif ":" in inp:
        #IPv6
        address = "".join(re.findall(r'[^ ]*]', inp))[1:-1]
        port = "".join(re.findall(r'][^ ]*', inp))[2:]
    return address,port


def code_ip_type(inp):
    if ".onion" in inp:
        return "Onion"
    elif "." in inp:
        return "IPv4"
    elif ":" in inp:
        return "IPv6"
    else:
        return "Unknown"


def statistics_detection_time():
    half_time_set = {"IPv4/IPv4": [], "IPv4/IPv6": [], "IPv4/Onion": [],
                      "IPv6/IPv6": [], "IPv6/Onion": [], "Onion/Onion": []}
    total_time_set = {"IPv4/IPv4": [], "IPv4/IPv6": [], "IPv4/Onion": [],
                      "IPv6/IPv6": [], "IPv6/Onion": [], "Onion/Onion": []}
    half_num = 0
    total_num = 0
    for i in [220220,220221,220222,220223,220224,220225,220226]:
      for j in ['conn_pool','addr_cache_valid']:
        with open('tests/'+j+'/'+str(i)+'/result.log','r+') as f:
            line = f.readline()
            while line:
                if "True" in line:
                    addr_a = "".join(re.findall(r'[^ ]* ', line))[:-6]
                    addr_b = "".join(re.findall(r' [^ ]* ', line))[1:-6]
                    next_line = next(f)
                    ts = int("".join(re.findall(r'耗时：[^ ]*s', next_line))[3:-1])
                    if "{}/{}".format(code_ip_type(addr_a), code_ip_type(addr_b)) in total_time_set:
                        total_time_set["{}/{}".format(code_ip_type(addr_a), code_ip_type(addr_b))].append(ts)
                        total_num += 1
                    else:
                        total_time_set["{}/{}".format(code_ip_type(addr_b), code_ip_type(addr_a))].append(ts)
                        total_num += 1
                if "False" in line:
                    addr_a = "".join(re.findall(r'[^ ]* ', line))[:-6]
                    addr_b = "".join(re.findall(r' [^ ]* ', line))[1:-6]
                    next_line = next(f)
                    ts = int("".join(re.findall(r'耗时：[^ ]*s', next_line))[3:-1])
                    if "{}/{}".format(code_ip_type(addr_a), code_ip_type(addr_b)) in half_time_set:
                        half_num += 1
                        half_time_set["{}/{}".format(code_ip_type(addr_a), code_ip_type(addr_b))].append(ts)
                    else:
                        half_num += 1
                        half_time_set["{}/{}".format(code_ip_type(addr_b), code_ip_type(addr_a))].append(ts)
                line = f.readline()

    print(half_num)
    print(total_num)
    df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in half_time_set.items()]))
    print(df)
    print(df.describe())
    plt.rcParams['figure.figsize'] = (6, 4.5)
    # plt.title("不同多址情形第一阶段探测时间分布图")
    plt.boxplot(x=(half_time_set["IPv4/IPv4"],half_time_set["IPv4/IPv6"], half_time_set["IPv4/Onion"],
                      half_time_set["IPv6/IPv6"], half_time_set["IPv6/Onion"], half_time_set["Onion/Onion"]),  # 指定绘图数据
                # patch_artist=True,  # 要求用自定义颜色填充盒形图，默认白色填充
                # showmeans=True,  # 以点的形式显示均值
                boxprops={'color': 'black'},  # 设置箱体属性，如边框色和填充色
                # 设置异常点属性，如点的形状、填充色和点的大小
                flierprops={'marker': 'o',  'markersize': 3},
                # 设置均值点的属性，如点的形状、填充色和点的大小
                # meanprops={'marker': 'D', 'markerfacecolor': 'blue', 'markersize': 4},
                # 设置中位数线的属性，如线的类型和颜色
                medianprops={'linestyle': '--', 'color': 'orange'},
                labels=["IPv4/IPv4","IPv4/IPv6","IPv4/Onion","IPv6/IPv6","IPv6/Onion","Onion/Onion"]  # 删除x轴的刻度标签，否则图形显示刻度标签为1
                )
    # plt.xlabel("地址对所属网络类型")
    # plt.ylabel("攻击时长（s）")
    # plt.grid(linestyle="--", alpha=0.5)
    # plt.savefig('figures/不同多址情形第一阶段攻击时长分布箱形图.png', dpi=300)
    plt.xlabel("Network types")
    plt.ylabel("Attack duration (s)")
    plt.grid(linestyle="--", alpha=0.5)
    plt.savefig('figures/half-duration.png', dpi=300)
    plt.show()


    df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in total_time_set.items()]))
    print(df)
    print(df.describe())
    plt.rcParams['figure.figsize'] = (6, 4.5)
    # plt.title("不同多址情形完整探测时间分布图")
    plt.boxplot(x=(total_time_set["IPv4/IPv4"],total_time_set["IPv4/IPv6"], total_time_set["IPv4/Onion"],
                      total_time_set["IPv6/IPv6"], total_time_set["IPv6/Onion"], total_time_set["Onion/Onion"]),  # 指定绘图数据
                # patch_artist=True,  # 要求用自定义颜色填充盒形图，默认白色填充
                # showmeans=True,  # 以点的形式显示均值
                # boxprops={'color': 'steelblue'},  # 设置箱体属性，如边框色和填充色
                boxprops={'color': 'black'},
                # 设置异常点属性，如点的形状、填充色和点的大小
                flierprops={'marker': 'o', 'markersize': 3},
                # 设置均值点的属性，如点的形状、填充色和点的大小
                # meanprops={'marker': 'D', 'markerfacecolor': 'blue', 'markersize': 4},
                # 设置中位数线的属性，如线的类型和颜色
                medianprops={'linestyle': '--', 'color': 'orange'},
                labels=["IPv4/IPv4","IPv4/IPv6","IPv4/Onion","IPv6/IPv6","IPv6/Onion","Onion/Onion"]  # 删除x轴的刻度标签，否则图形显示刻度标签为1
                )
    # plt.xlabel("地址对所属网络类型")
    # plt.ylabel("攻击时长（s）")
    # plt.grid(linestyle="--", alpha=0.5)
    # plt.savefig('figures/不同多址情形完整攻击时长分布箱形图.png', dpi=300)
    plt.xlabel("Network types")
    plt.ylabel("Attack duration (s)")
    plt.grid(linestyle="--", alpha=0.5)
    plt.savefig('figures/total-duration.png', dpi=300)
    plt.show()
    # df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in total_time_set.items()]))
    # print(df)
    # print(df.describe())
    # plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']
    # filerprops = dict(marker='o', markerfacecolor='green', markersize=12,
    #                   linestyle='none')
    # df.plot.box(title="不同多址情形探测时间分布箱形图")
    # plt.grid(linestyle="--", alpha=0.3)
    # plt.show()


def statistics_number_of_open_connections():
    date = "2022-03-02"
    session = connect_db()
    open_conns = [int(y.connslots) for y in
             session.query(Node.connslots).filter(and_(Node.date == date, Node.connslots != None)).all()]
    y = []
    x = [j for j in range(115,-1,-1)]
    for j in range(115,-1,-1):
        y.append(sum(i>=j for i in open_conns))
    # print(x, y)

    y = [int(i / 8601 * 100.0) for i in y]
    print(x)
    print(y)
    y[-1] = 100
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.plot(x, y, c='black', linewidth=0.4)
    # plt.scatter(x, y, c='black')
    y_ticks = range(110)
    plt.yticks(y_ticks[::10])
    x_ticks = range(120)
    plt.xticks(x_ticks[::10])
    plt.gca().invert_xaxis()
    plt.xlim((115, 0))
    plt.ylim((0, 100))
    plt.grid(True, linestyle='--', alpha=0.3)
    # plt.xlabel("建立的连接数")
    # plt.ylabel("% 比特币可达地址")
    # plt.savefig('figures/3月2日比特币主网可达地址可连接数分布.png', dpi=300)
    plt.xlabel("Number of connections established")
    plt.ylabel("% Bitcoin reachable addresses")
    plt.savefig('figures/connections-available.png', dpi=300)
    # plt.title("可建立连接数的分布折线图")
    plt.show()


def extracting_conn_timing():
    nodes = []
    with open("tests/analysis/node3/debug.txt") as f:
        for line in f.readlines():
            if "Receiving" in line:
                ts = "".join(re.findall( r'[^ ]* Receiving', line))[:-10]
                timestamp = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                peer = "".join(re.findall( r'from [^ ]*', line))[5:-1]
                nodes.append({'timestamp':timestamp,'type':'income','num':1,'peer':peer})
            if "Disconnecting" in line:
                ts = "".join(re.findall(r'[^ ]* Disconnecting', line))[:-14]
                timestamp = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                peer = "".join(re.findall( r'from [^ ]*', line))[5:-1]
                nodes.append({'timestamp': timestamp, 'type': 'disconnect','num':1,'peer':peer })
    nodes = pd.DataFrame(nodes)
    nodes.to_csv("tests/analysis/node1/debug.csv", index=False)


def detect_outliers(ori_data, threshold=3):
    data = []
    for i in ori_data:
        if i <= 20:
            data.append(i)
    mean_d = np.mean(data)
    std_d = np.std(data)
    outliers = []
    for y in data:
        z_score = (y - mean_d) / std_d
        if np.abs(z_score) <= threshold:
            outliers.append(y)
    return outliers


def statistics_lost_connections_distribution():
    lost = []
    for i in range(2,3):
        with open("tests/slots_monitor/node"+str(i)+"/result.log") as f:
            for line in f.readlines():
                 lost.append(int("".join(re.findall(r'lost num: [^ ]*', line))[9:-1]))
    lost = detect_outliers(lost)
    lost = pd.value_counts(lost,normalize=True)
    lost.sort_index(inplace=True)
    for i in range(lost.size):
        if type(lost.iloc[i]) == np.float64:
            lost.iloc[i] = lost.iloc[i] * 100
        else:
            pass
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    y_ticks = range(110)
    plt.yticks(y_ticks[::10])
    x_ticks = range(max(lost.index))
    plt.xticks(x_ticks[::1])
    plt.xlim((min(lost.index), max(lost.index)))
    plt.ylim((min(lost.values), 100))
    plt.plot(list(lost.index), list(lost.values), c='black', linewidth=0.4)
    plt.scatter(list(lost.index), list(lost.values), c='black',s=10.0)
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.show()
    return lost


def statistics_new_connections_distribution():
    new = []
    for i in range(2, 3):
        with open("tests/slots_monitor/node"+str(i)+"/result.log") as f:
            for line in f.readlines():
                new.append(int("".join(re.findall(r'new num: [^ ]*', line))[9:-1]))
    new = detect_outliers(new)
    new = pd.value_counts(new,normalize=True)
    new.sort_index(inplace=True)
    for i in range(new.size):
        if type(new.iloc[i]) == np.float64:
            new.iloc[i] = new.iloc[i] * 100
        else:
            pass
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    y_ticks = range(110)
    plt.yticks(y_ticks[::10])
    x_ticks = range(max(new.index))
    plt.xticks(x_ticks[::1])
    plt.xlim((min(new.index), max(new.index)))
    plt.ylim((min(new.values), 100))
    plt.plot(list(new.index), list(new.values), c='black', linewidth=0.4)
    plt.scatter(list(new.index), list(new.values), c='black',s=10.0)
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.show()
    return new


def statistics_slots_fluctuation(diff):
    slots = []
    ts = []
    changes = []
    # for i in range(2,3):
    #     with open("tests/slots_monitor/node"+str(i)+"/result.log") as f:
    #         for line in f.readlines():
    #             slot = int("".join(re.findall(r'peers num: [^,]*', line))[11:])
    #             tmp = datetime.strptime("".join(re.search( r'\[.*?\]', line).group())[1:-1], "%Y-%m-%d %H:%M")
    #             slots.append(slot)
    #             ts.append(tmp)
    for i in range(1,6):
        with open("tests/slots_monitor/node"+str(i)+"/result.log", 'r+') as f:
            line = f.readline()
            while line:
                slot = int("".join(re.findall(r'peers num: [^,]*', line))[11:])
                for j in range(0,int(int(diff)/60)):
                    next_line = next(f, None)
                if next_line:
                    next_slot = int("".join(re.findall(r'peers num: [^,]*', next_line))[11:])
                    change_slot = next_slot - slot
                    changes.append(change_slot)
                else:
                    break
                line = f.readline()
    changes = pd.value_counts(changes, normalize=True)
    changes.sort_index(inplace=True)
    for i in range(changes.size):
        if type(changes.iloc[i]) == np.float64:
            changes.iloc[i] = changes.iloc[i] * 100
        else:
            pass
    changes = pd.DataFrame(changes)
    changes.columns = [diff]

    # plt.rcParams['figure.figsize'] = (6.5, 4.5)
    # plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']
    # plt.plot(list(changes.index), changes[diff], marker='|', linestyle='-', mfc='w', c='black', label='∆t=60s',
    #          linewidth=0.4, markersize=3)
    # # plt.plot(ts, changes, c='black', linewidth=0.4)
    # # plt.scatter(list(new.index), list(new.values), c='black',s=10.0)
    # plt.ylim((0, 100))
    # plt.grid(True, linestyle='--', alpha=0.3)
    # plt.show()
    return changes


def draw_node_slots():
    slots = {}
    ts = {}
    for i in range(1,6):
        count = 0
        with open("tests/slots_monitor/node"+str(i)+"/result.log") as f:
            for line in f.readlines():
                count += 1
                if count%10 != 0:
                    continue
                slot = int("".join(re.findall(r'peers num: [^,]*', line))[11:])
                tmp = datetime.strptime("".join(re.search( r'\[.*?\]', line).group())[1:-1], "%Y-%m-%d %H:%M")
                if i not in slots:
                    slots[i] = []
                slots[i].append(slot)
                if i not in ts:
                    ts[i] = []
                ts[i].append(tmp)

    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.subplot(5, 1, 1)
    plt.plot(ts[1], slots[1], marker='|', linestyle='-', mfc='w', c='black', label='∆t=60s',
             linewidth=0.4, markersize=3)
    plt.ylim((0, 120))
    plt.subplot(5, 1, 2)
    plt.plot(ts[2], slots[2], marker='|', linestyle='-', mfc='w', c='black', label='∆t=60s',
             linewidth=0.4, markersize=3)
    plt.ylim((0, 120))
    plt.subplot(5, 1, 3)
    plt.plot(ts[3], slots[3], marker='|', linestyle='-', mfc='w', c='black', label='∆t=60s',
             linewidth=0.4, markersize=3)
    plt.ylim((0, 120))
    plt.subplot(5, 1, 4)
    plt.plot(ts[4], slots[4], marker='|', linestyle='-', mfc='w', c='black', label='∆t=60s',
             linewidth=0.4, markersize=3)
    plt.ylim((0, 120))
    plt.subplot(5, 1, 5)
    plt.plot(ts[5], slots[5], marker='|', linestyle='-', mfc='w', c='black', label='∆t=60s',
             linewidth=0.4, markersize=3)
    plt.ylim((0, 120))
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.show()
    return slots


def draw_slots_fluctuation():
    changes_60 = statistics_slots_fluctuation(60)
    print(changes_60)
    changes_120 = statistics_slots_fluctuation(120)
    print(changes_120)
    changes_180 = statistics_slots_fluctuation(180)
    print(changes_180)
    changes_360 = statistics_slots_fluctuation(360)
    print(changes_360)
    # evict_420 = statistics_evict_connections_distribution(420)
    # evict_420 = pd.DataFrame(evict_420)
    # evict_420.columns = ['420']
    changes = changes_60.join([changes_120, changes_180, changes_360], how='outer').fillna(value=0)
    # evict_420 = statistics_evict_connections_distribution(420)
    plt.rcParams['figure.figsize'] = (6, 4.5)
    plt.plot( list(changes.index), changes[60], marker='|', linestyle='-',mfc='w', c='black', label='∆t=60s',linewidth=0.4,markersize=3)
    plt.plot( list(changes.index), changes[120], marker='x', linestyle='--',mfc='w', c='black',label='∆t=120s',linewidth=0.4,markersize=3)
    plt.plot( list(changes.index), changes[180], marker='+', linestyle=':',mfc='w', c='black',label='∆t=180s',linewidth=0.4,markersize=3)
    plt.plot( list(changes.index), changes[360], marker='s', linestyle='-.', mfc='w', c='black',label='∆t=360s',linewidth=0.4,markersize=3)
    plt.ylim(ymin=0)
    # plt.xlim(xmin=0)
    # plt.xlabel("波动连接数")
    # plt.ylabel("% 实验次数")
    plt.xlabel("Number of fluctuating connections")
    plt.ylabel("% of experiments")
    # plt.plot(evict_60.keys(), evict_60['60'], c='red', label="得分")
    # plt.plot(game, rebounds, c='green', linestyle='--', label="篮板")
    # plt.plot(game, assists, c='blue', linestyle='-.', label="助攻")
    # plt.scatter(game, scores, c='red')
    # plt.scatter(game, rebounds, c='green')
    # plt.scatter(game, assists, c='blue')
    plt.legend(loc='best')
    plt.grid(True, linestyle='--', alpha=0.5)
    # plt.savefig('figures/地面实况节点的连接波动速率分布折线图.png', dpi=300)
    plt.savefig('figures/connections-fluctuate.png', dpi=300)
    plt.show()


def statistics_evict_connections_distribution(diff):
    files = os.listdir('tests/normal_evict_conns_monitor')  # files是一个列表
    evict = []

    for file in files:
        readDir = "tests/normal_evict_conns_monitor/"+file
        writeDir = "tests/normal_clear_evict_conns_monitor/"+file
        lines_seen = set()
        outfile = open(writeDir, "w")
        print(readDir)
        f = open(readDir, "r")
        for line in f:
            if line not in lines_seen:
                outfile.write(line)
                lines_seen.add(line)
        outfile.close()

    for file in files:
        with open("tests/normal_clear_evict_conns_monitor/"+file,'r+') as f:
            line = f.readline()
            while line:
                if "empty" in line:
                    ts = "".join(re.search( r'\[.*?\]', line).group())[1:-1]
                    start_timestamp = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    node = "".join(re.findall(r'\] [^ ]* ', line))[2:-2]
                    empty_slots = "".join(re.findall(r': [^ ]* empty', line))[2:-6]
                    if int(empty_slots) == 0 :
                        line = f.readline()
                        continue
                    tmp = 0
                    last_timestamp = start_timestamp
                    n = 0
                    tried = 0
                    while True:
                        next_line = next(f, None)
                        if next_line and (node in next_line) and ("lost" in next_line):
                            ts = "".join(re.search( r'\[.*?\]', next_line).group())[1:-1]
                            timestamp = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                            if math.isclose((timestamp-start_timestamp).total_seconds(),int(diff),abs_tol=2):
                                # last_timestamp = timestamp
                                tmp += int("".join(re.findall(r'lost: [^ ]*', next_line))[6:-1])
                                evict.append(tmp)
                                break
                            elif timestamp != last_timestamp:
                                last_timestamp = timestamp
                                tmp += int("".join(re.findall(r'lost: [^ ]*', next_line))[6:-1])
                                n += 1
                            elif timestamp == last_timestamp:
                                continue
                        elif next_line and (node in next_line) and n < int(diff) / 60:
                            break
                        elif next_line and (node not in next_line) and n <= int(diff)/60 and tried < 5:
                            tried += 1
                            continue
                        else:
                            break
                line = f.readline()
    print(evict)
    print(len(evict))
    print(np.mean(evict))
    print(np.var(evict))
    evict = pd.value_counts(evict,normalize=True)
    evict.sort_index(inplace=True)
    for i in range(evict.size):
        if type(evict.iloc[i]) == np.float64:
            evict.iloc[i] = evict.iloc[i] * 100
        else:
            pass
    # plt.rcParams['figure.figsize'] = (6.5, 4.5)
    # plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']
    # y_ticks = range(110)
    # plt.yticks(y_ticks[::10])
    # x_ticks = range(max(evict.index))
    # plt.xticks(x_ticks[::1])
    # plt.xlim((min(evict.index), max(evict.index)))
    # plt.ylim((min(evict.values), 100))
    # plt.plot(list(evict.index), list(evict.values), c='black', linewidth=0.4)
    # plt.scatter(list(evict.index), list(evict.values), c='black',s=10.0)
    # plt.grid(True, linestyle='--', alpha=0.3)
    # plt.show()
    return evict


def test():
    evict_60 = statistics_evict_connections_distribution(60)
    evict_60 = pd.DataFrame(evict_60)
    evict_60.columns = ['60']
    print(evict_60)
    evict_120 = statistics_evict_connections_distribution(120)
    evict_120 = pd.DataFrame(evict_120)
    evict_120.columns = ['120']
    print(evict_120)
    evict_180 = statistics_evict_connections_distribution(180)
    evict_180 = pd.DataFrame(evict_180)
    evict_180.columns = ['180']
    print(evict_180)
    # evict_240 = statistics_evict_connections_distribution(240)
    # evict_300 = statistics_evict_connections_distribution(300)
    evict_360 = statistics_evict_connections_distribution(360)
    evict_360 = pd.DataFrame(evict_360)
    evict_360.columns = ['360']
    print(evict_360)
    # evict_420 = statistics_evict_connections_distribution(420)
    # evict_420 = pd.DataFrame(evict_420)
    # evict_420.columns = ['420']
    evict = evict_60.join([evict_120, evict_180, evict_360], how='outer').fillna(value=0)
    # evict_420 = statistics_evict_connections_distribution(420)
    plt.rcParams['figure.figsize'] = (6, 4.5)
    # evict.plot()
    plt.plot( list(evict.index), evict['60'], marker='|', linestyle='-',mfc='w', c='black', label='∆t=60s',linewidth=0.4,markersize=3)
    plt.plot( list(evict.index), evict['120'], marker='x', linestyle='--',mfc='w', c='black',label='∆t=120s',linewidth=0.4,markersize=3)
    plt.plot( list(evict.index), evict['180'], marker='+', linestyle=':',mfc='w', c='black',label='∆t=180s',linewidth=0.4,markersize=3)
    plt.plot( list(evict.index), evict['360'], marker='s', linestyle='-.', mfc='w', c='black',label='∆t=360s',linewidth=0.4,markersize=3)
    plt.ylim(ymin=0)
    plt.xlim(xmin=0)
    # plt.xlabel("驱逐连接数")
    # plt.ylabel("% 实验次数")
    plt.xlabel("Number of evicted connections")
    plt.ylabel("% of experiments")
    # plt.plot(evict_60.keys(), evict_60['60'], c='red', label="得分")
    # plt.plot(game, rebounds, c='green', linestyle='--', label="篮板")
    # plt.plot(game, assists, c='blue', linestyle='-.', label="助攻")
    # plt.scatter(game, scores, c='red')
    # plt.scatter(game, rebounds, c='green')
    # plt.scatter(game, assists, c='blue')
    plt.legend(loc='best')
    plt.grid(True, linestyle='--', alpha=0.5)
    # plt.savefig('figures/多址节点的连接正常驱逐频数分布折线图.png', dpi=300)
    plt.savefig('figures/normal-eviction.png', dpi=300)
    plt.show()


def statistics_addr_fingerprints():
    addr_fps = [3910,3894,3889,3937,4008,3983,3980]
    x = pd.date_range(start='20220220', end='20220226').tolist()
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    # y_ticks = range(110)
    # plt.yticks(y_ticks[::10])
    # x_ticks = range(max(evict.index))
    # plt.xticks(x_ticks[::1])
    # plt.xlim((min(evict.index), max(evict.index)))
    plt.xticks(rotation=15)
    plt.ylim((0,4500))
    plt.plot(x,addr_fps, c='black', linewidth=0.4)
    plt.scatter(x,addr_fps, c='black',s=10.0)
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.show()


def statistics_addrbase_size_change():
    node1 = [65192, 65215, 65154, 65318, 65461, 65477, 65611]
    node2 = [64763, 64779, 64634, 64732, 64917, 65050, 65028]
    node3 = [65078, 65000, 65078, 65226, 65436, 65429, 65448]
    node4 = [67631, 67630, 67656, 67609, 67938, 68056, 68009]
    node5 = [65229, 65282, 65280, 65428, 65512, 65638, 65671]
    x = pd.date_range(start='20220227', end='20220305').tolist()
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.plot( x, node1, marker='|', linestyle='-',mfc='w', c='black', label='Node1',linewidth=0.4,markersize=3)
    plt.plot( x, node2, marker='x', linestyle='--',mfc='w', c='black',label='Node2',linewidth=0.4,markersize=3)
    plt.plot( x, node3, marker='*', linestyle=':',mfc='w', c='black',label='Node3',linewidth=0.4,markersize=3)
    plt.plot( x, node4, marker='s', linestyle='dotted',  c='black',label='Node4',linewidth=0.4,markersize=3)
    plt.plot( x, node5, marker='+', linestyle='-.', mfc='w',c='black', label='Node5',linewidth=0.4,markersize=3)
    plt.ylim(ymin=0,ymax=70000)
    plt.xticks(rotation=15)
    # plt.xlabel('日期')
    # plt.ylabel('节点地址库大小')
    plt.xlabel('Date')
    plt.ylabel('Node address database size')
    plt.legend()
    # plt.savefig('figures/节点地址数据库大小变化情况.png', dpi=300,bbox_inches='tight')
    plt.savefig('figures/addrman-size.png', dpi=300,bbox_inches='tight')
    plt.show()


def statistics_FN_change():
    node1 = [18,7,6,3,2,0,0,0]
    x = [1,2,3,4,5,6,7,8]
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.bar( x, node1,color='b')
    # plt.ylim(ymin=0,ymax=70000)
    # plt.xlabel('实验次数')
    # plt.ylabel('假阴性率 (%)')
    # plt.savefig('figures/假阴性率随实验次数增加而下降.png', dpi=300)
    plt.xlabel('Runs of attacks')
    plt.ylabel('False-negative rate (%)')
    plt.savefig('figures/false-negative.png', dpi=300)
    plt.show()


def calculate_syncrate():
    start_time = 2022022400
    cluster_nodes = {}
    # targets = []
    i = 1
    while True:
        file1 = 'nodes_info/220224/'+str(start_time+(i-1)*1)+'.txt'
        # file2 = 'nodes_info/220224/' + str(start_time+i*1) + '.txt'
        try:
            with open(file1,'r+') as f1:
                json_str1 = json.loads(f1.read())
            # with open(file2, 'r+') as f2:
            #     json_str2 = json.loads(f2.read())
        except FileNotFoundError:
            print(file1)
            # print(file2)
            break
        nodes_value1 = json_str1.get("nodes")
        ts1 = json_str1.get("timestamp")
        # nodes_value2 = json_str2.get("nodes")
        # ts2 = json_str2.get("timestamp")

        for IPport in nodes_value1.keys():
            if not "Satoshi:22.0.0" in nodes_value1[IPport][1]:
                continue
            # if IPport in nodes_value2.keys():
            version = nodes_value1[IPport][0]
            user_agent = nodes_value1[IPport][1]
            services = nodes_value1[IPport][3]
                # height1 = nodes_value1[IPport][4]
            height1 = nodes_value1[IPport][4]
                # sync_rate = round((height1-height2)/((ts1-ts2)/3600), 4)
            if IPport not in cluster_nodes:
                cluster_nodes[IPport] = {'vus':str(version)+user_agent+str(services),'height'+str(i):height1}
            else:
                    # cluster_nodes[IPport]['sync'+str(i)] = sync_rate
                cluster_nodes[IPport]['height' + str(i)] = height1
                # if IPport not in targets:
                #     targets.append(IPport)
        i += 1
    pd.DataFrame.from_dict(data=cluster_nodes, orient='index').to_csv('tests/analysis/cluster_nodes.csv', header=False)
    print(cluster_nodes)

    results = {}
    filterd = []
    # print(len(targets))
    # for x in range(0,len(targets)):
    #     if x in filterd:
    #         continue
    #     for y in range(x,len(targets)):
    #         if y in filterd:
    #             continue
    #         if cluster_nodes[targets[x]]['vus'] == cluster_nodes[targets[y]]['vus'] and \
    #                 (math.isclose(cluster_nodes[targets[x]]['height'+str(count)],cluster_nodes[targets[y]]['height'+str(count)], abs_tol=2) for count in range(1,18)):
    #             if targets[x] not in results:
    #                 results[targets[x]] = {targets[x], targets[y]}
    #             else:
    #                 results[targets[x]].add(targets[y])
    #             if x not in filterd:
    #                 filterd.append(x)
    #             if y not in filterd:
    #                 filterd.append(y)
    for x in cluster_nodes:
        if x in filterd:
            continue
        for y in cluster_nodes:
            if y in filterd:
                continue
            if cluster_nodes[x]['vus'] != cluster_nodes[y]['vus']:
                continue
            Flag = False
            num = 0
            pct = 0
            total = 0
            for count in range(1, 24):
                if ('height'+str(count) in cluster_nodes[x]) and ('height'+str(count) in cluster_nodes[y]):
                    if math.isclose(cluster_nodes[x]['height'+str(count)],cluster_nodes[y]['height'+str(count)], abs_tol=6):
                        pct += 1
                    total += 1
                    pass
                elif (('height'+str(count) not in cluster_nodes[x]) or ('height'+str(count) not in cluster_nodes[y])) and num < 10:
                    num += 1
                    continue
                else:
                    break
            if total and pct/total >= 0.7:
                Flag = True
            if Flag == True:
                if x not in results:
                    results[x] = {x,y}
                else:
                    results[x].add(y)
                if x not in filterd:
                    filterd.append(x)
                if y not in filterd:
                    filterd.append(y)
    pd.DataFrame.from_dict(data=results, orient='index').to_csv('tests/analysis/results.csv', header=False)
    with open('tests/analysis/filterd.txt','w+') as f:
        f.write(json.dumps(filterd))
    # if nodes_value1[IPport][0] == nodes_value2[IPport][0] and nodes_value1[IPport][1] == nodes_value2[IPport][1] \
    #         and nodes_value1[IPport][3] == nodes_value2[IPport][3] and math.isclose(nodes_value1[IPport][4],
    #                                                                                 nodes_value2[IPport][4], abs_tol=2):
    #     pass
    # else:
    #     pass


def statistics_addrbase_overlap_change():
    node = [5835,5993,6234,6261,6189,6386,6485,6593,6721,6999,6919,7164,7012,7179,7025]
    # x = pd.date_range(start='20220302', end='20220305').tolist()
    x = ['2022-03-02','2022-03-03','2022-03-04','2022-03-05','2022-03-06','2022-03-10','2022-03-11','2022-03-12','2022-03-13','2022-03-14','2022-03-15','2022-03-16','2022-03-17','2022-03-18','2022-03-19']
    print(x)
    plt.rcParams['figure.figsize'] = (6.5, 4.5)
    plt.plot( x, node, marker='|', linestyle='-',mfc='w', c='black',linewidth=0.4,markersize=3)
    plt.ylim(ymin=0,ymax=7500)
    plt.xticks(rotation=25)
    # plt.xlabel('日期')
    # plt.ylabel('节点地址库重叠地址数')
    # plt.savefig('figures/地面实况节点日均地址库重叠地址数变化折线图.png', dpi=300,bbox_inches='tight')
    plt.xlabel('Date')
    plt.ylabel('Number of overlapping addresses')
    plt.savefig('figures/overlap-nodes.png', dpi=300,bbox_inches='tight')
    plt.show()


def analysis_TH():
    changes_60 = statistics_slots_fluctuation(60)
    change_num_60 = list(changes_60.index)
    change_pro_60 = list(changes_60.values)
    changes_120 = statistics_slots_fluctuation(120)
    change_num_120 = list(changes_120.index)
    change_pro_120 = list(changes_120.values)
    changes_180 = statistics_slots_fluctuation(180)
    change_num_180 = list(changes_180.index)
    change_pro_180 = list(changes_180.values)
    changes_360 = statistics_slots_fluctuation(360)
    change_num_360 = list(changes_360.index)
    change_pro_360 = list(changes_360.values)

    evict_60 = statistics_evict_connections_distribution(60)
    evict_60 = pd.DataFrame(evict_60)
    evict_60.columns = ['60']
    evict_num_60 = list(evict_60.index)
    evict_pro_60 = list(evict_60.values)
    evict_120 = statistics_evict_connections_distribution(120)
    evict_120 = pd.DataFrame(evict_120)
    evict_120.columns = ['120']
    evict_num_120 = list(evict_120.index)
    evict_pro_120 = list(evict_120.values)
    evict_180 = statistics_evict_connections_distribution(180)
    evict_180 = pd.DataFrame(evict_180)
    evict_180.columns = ['180']
    evict_num_180 = list(evict_180.index)
    evict_pro_180 = list(evict_180.values)
    evict_360 = statistics_evict_connections_distribution(360)
    evict_360 = pd.DataFrame(evict_60)
    evict_360.columns = ['360']
    evict_num_360 = list(evict_360.index)
    evict_pro_360 = list(evict_360.values)
    total_60 = {}
    for i in range(0,len(change_num_60)):
        for j in range(0,len(evict_num_60)):
            tonum_60 = change_num_60[i] - evict_num_60[j]
            topro_60 = change_pro_60[i] * evict_pro_60[j]
            if tonum_60 in total_60:
                total_60[tonum_60] += topro_60
            else:
                total_60[tonum_60] = topro_60
    for q in total_60:
        total_60[q] = total_60[q]/100
    total_60 = pd.DataFrame(total_60, index=[0]).T
    total_60.sort_index(inplace=True)
    total_60.columns = ['60']
    print(total_60)

    total_120 = {}
    for i in range(0,len(change_num_120)):
        for j in range(0,len(evict_num_120)):
            tonum_120 = change_num_120[i] - evict_num_120[j]
            topro_120 = change_pro_120[i] * evict_pro_120[j]
            if tonum_120 in total_120:
                total_120[tonum_120] += topro_120
            else:
                total_120[tonum_120] = topro_120
    for q in total_120:
        total_120[q] = total_120[q]/100
    total_120 = pd.DataFrame(total_120, index=[0]).T
    total_120.sort_index(inplace=True)
    total_120.columns = ['120']
    print(total_120)

    total_180 = {}
    for i in range(0,len(change_num_180)):
        for j in range(0,len(evict_num_180)):
            tonum_180 = change_num_180[i] - evict_num_180[j]
            topro_180 = change_pro_180[i] * evict_pro_180[j]
            if tonum_180 in total_180:
                total_180[tonum_180] += topro_180
            else:
                total_180[tonum_180] = topro_180
    for q in total_180:
        total_180[q] = total_180[q]/100
    total_180 = pd.DataFrame(total_180, index=[0]).T
    total_180.sort_index(inplace=True)
    total_180.columns = ['180']
    print(total_180)

    total_360 = {}
    for i in range(0,len(change_num_360)):
        for j in range(0,len(evict_num_360)):
            tonum_360 = change_num_360[i] - evict_num_360[j]
            topro_360 = change_pro_360[i] * evict_pro_360[j]
            if tonum_360 in total_360:
                total_360[tonum_360] += topro_360
            else:
                total_360[tonum_360] = topro_360
    for q in total_360:
        total_360[q] = total_360[q]/100
    total_360 = pd.DataFrame(total_360, index=[0]).T
    total_360.sort_index(inplace=True)
    total_360.columns = ['360']
    print(total_360)

    total_df = total_60.join([total_120, total_180, total_360], how='outer').fillna(value=0)
    total_df.sort_index(inplace=True)

    plt.rcParams['figure.figsize'] = (6, 4.5)
    plt.plot( list(total_df.index), list(total_df['60']), marker='|', linestyle='-',mfc='w', c='black', label='∆t=60s',linewidth=0.4,markersize=3)
    plt.plot( list(total_df.index), list(total_df['120']), marker='x', linestyle='--',mfc='w', c='black',label='∆t=120s',linewidth=0.4,markersize=3)
    plt.plot( list(total_df.index), list(total_df['180']), marker='+', linestyle=':',mfc='w', c='black',label='∆t=180s',linewidth=0.4,markersize=3)
    plt.plot( list(total_df.index), list(total_df['360']), marker='s', linestyle='-.', mfc='w', c='black',label='∆t=360s',linewidth=0.4,markersize=3)
    plt.ylim((0, 100))
    plt.xlabel("空连接槽波动数")
    plt.ylabel("% 实验次数")
    plt.legend(loc='best')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.savefig('节点空连接槽波动阈值概率密度分布折线图.png', dpi=300)
    plt.show()


if __name__ == '__main__':
    print(statistics_detection_time())
    # statistics_number_of_open_connections()
    # extracting_conn_timing()

    # lost = statistics_lost_connections_distribution()
    # print(lost)
    # new = statistics_new_connections_distribution()
    # print(new)
    # statistics_evict_connections_distribution(diff)
    # test()

    # statistics_addr_fingerprints()

    # statistics_slots_fluctuation(60)
    # draw_slots_fluctuation()
    # draw_node_slots()

    # statistics_addrbase_size_change()

    # calculate_syncrate()

    # statistics_addrbase_overlap_change()

    # analysis_TH()

    # statistics_FN_change()
