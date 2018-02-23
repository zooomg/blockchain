import json
from urllib.parse import urlparse
import threading
import requests
from time import time


# 우리가 보낼 ip 주소들을 nodes_addr에 추가하는데, len(nodes_addr)이 정확한 개수에 도달하면, get_info실행
nodes_addr = ["http://172.17.67.233:5000",
              "http://172.17.67.233:5001",
              "http://172.17.64.177:5000",
              "http://172.17.64.177:5001"]

# nodes_addr = ["http://127.0.0.1:5002",
#               "http://127.0.0.1:5000",
#               "http://127.0.0.1:5001",
#               "http://127.0.0.1:5003"]

leader_id = None
leader_idx = -1
nodes = []

def init_genesis_block():
    """
    Init genesis block

    :return: Genesis block
    """

    # TODO : change block
    block = {
        'index': 1,
        'timestamp': time(),
        'transactions': [],
    }
    return block

def get_info():
    flag = True

    for node in nodes_addr:
        url = node + '/id'
        response = requests.get(url=url)
        node_id, node_pubkey = None, None

        if response.status_code == 200:
            node_id = response.json()['id']

        url = node + '/pubkey'
        response = requests.get(url=url)

        if response.status_code == 200:
            node_pubkey = response.json()['pubkey']

        nodes.append({'id': node_id, 'address': node, 'pubkey': node_pubkey, 'leader': flag})
        if flag == True:
            global leader_id
            leader_id = node_id

        flag = False

def send_info():
    data = {'nodes': nodes, 'leader_idx': leader_idx}
    jdata = json.dumps(data)
    headers = {'Content-Type': 'application/json'}
    genesis_block = init_genesis_block()
    jblock = json.dumps(genesis_block)

    for node in nodes_addr:
        url = node + '/append_genesis'
        threading.Thread(target=data_thread, args=(url, headers, jblock)).start()

    for node in nodes_addr:
        url = node + '/nodes/register'
        threading.Thread(target=data_thread, args=(url, headers, jdata)).start()

def data_thread(url, headers, data):
    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 201:
        msg = response.json()['message']
        # total_nodes = response.json()['total_nodes']
        print(msg)
        # for t in total_nodes:
            # print(t)

# TODO : node ip 개수가 정해진 개수에 도달했을 때 << 구현
get_info() # 후에 이거 실행

# 이거는 리더 선택인데 걍 써도 됨
nodes = sorted(nodes, key=lambda k:k['id'])
for i in range(len(nodes)):
    if nodes[i].get('id') == leader_id:
        leader_idx = i

send_info()
