import json
import time

# 10号：7562 6264 6162 6065
# 11号：7640 6455 6345 6106
# 12号：7640 6539 6323 6142
# 13号：7990 6617 6448 6315
def calculate_overlap_nodes():
    # with open('tests/addrman_overlap/220319/nodeaddresses_1.txt','r+') as f:
    #     nodes_1 = json.loads(f.read())
    # with open('tests/addrman_overlap/220319/nodeaddresses_2.txt','r+') as f:
    #     nodes_2 = json.loads(f.read())
    # with open('tests/addrman_overlap/220319/nodeaddresses_3.txt','r+') as f:
    #     nodes_3 = json.loads(f.read())
    with open('tests/addrman_overlap/220319/nodeaddresses_4.txt','r+') as f:
        nodes_4 = json.loads(f.read())
    with open('tests/addrman_overlap/220319/nodeaddresses_5.txt','r+') as f:
        nodes_5 = json.loads(f.read())
    # print(len(nodes_1))
    # print(len(nodes_2))
    # print(len(nodes_3))
    # print(len(nodes_4))
    # print(len(nodes_5))
    a,b,c,d = 0,0,0,0
    for node in nodes_4:
        # if node in nodes_2:
        #     a+=1
        # if node in nodes_3:
        #     b+=1
        # if node in nodes_4:
        #     c+=1
        if node in nodes_5:
            d+=1
    print(a,b,c,d)


def addrman_change_nodes():
    with open('tests/addrman_overlap/220302/nodeaddresses_1.txt','r+') as f:
        nodes_1 = json.loads(f.read())
    with open('tests/addrman_overlap/220303/nodeaddresses_1.txt','r+') as f:
        nodes_2 = json.loads(f.read())
    with open('tests/addrman_overlap/220310/nodeaddresses_1.txt','r+') as f:
        nodes_3 = json.loads(f.read())
    print(len(nodes_1))
    print(len(nodes_2))
    print(len(nodes_3))
    a,b = 0,0
    for node in nodes_1:
        if node in nodes_2:
            a+=1
        if node in nodes_3:
            b+=1
    print(a,b)

if __name__ == '__main__':
    # calculate_overlap_nodes()
    # print(d)
    addrman_change_nodes()