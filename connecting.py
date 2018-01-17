import json
from urllib.parse import urlparse
from uuid import uuid4

import requests

<<<<<<< HEAD
# nodes_addr = ["http://172.17.64.97:5000",
#               "http://172.17.64.175:5000",
#               "http://172.17.67.233:5000"]

=======
>>>>>>> 506a996774276dc363f662a60f354e74858ebf0b
nodes_addr = ["http://127.0.0.1:5000",
              "http://127.0.0.1:5001",
              "http://127.0.0.1:5002"]

<<<<<<< HEAD

nodes = []

def get_info():
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

        nodes.append({'id': node_id, 'address': node, 'pubkey': node_pubkey})
=======
nodes = []

def get_id():
    for node in nodes_addr:
        url = node + '/id'
        response = requests.get(url=url)
        if response.status_code == 200:
            node_id = response.json()['id']
            nodes.append({'id': node_id, 'address': node})
>>>>>>> 506a996774276dc363f662a60f354e74858ebf0b

def send_info():
    data = {'nodes': nodes}
    jdata = json.dumps(data)
    headers = {'Content-Type': 'application/json'}
<<<<<<< HEAD

=======
>>>>>>> 506a996774276dc363f662a60f354e74858ebf0b
    for node in nodes_addr:
        url = node + '/nodes/register'
        response = requests.post(url, headers=headers, data=jdata)

        if response.status_code == 200:
            msg = response.json()['message']
            total_nodes = response.json()['total_nodes']
            print(msg)
            for t in total_nodes:
                print(t)

<<<<<<< HEAD
get_info()
=======
get_id()
>>>>>>> 506a996774276dc363f662a60f354e74858ebf0b
send_info()

# 4번 부터 작성