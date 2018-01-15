import json
from urllib.parse import urlparse
from uuid import uuid4

import requests

nodes_addr = ["http://127.0.0.1:5000",
              "http://127.0.0.1:5001",
              "http://127.0.0.1:5002"]

nodes = []

def get_id():
    for node in nodes_addr:
        url = node + '/id'
        response = requests.get(url=url)
        if response.status_code == 200:
            node_id = response.json()['id']
            nodes.append({'id': node_id, 'address': node})

def send_info():
    data = {'nodes': nodes}
    jdata = json.dumps(data)
    headers = {'Content-Type': 'application/json'}
    for node in nodes_addr:
        url = node + '/nodes/register'
        response = requests.post(url, headers=headers, data=jdata)

        if response.status_code == 200:
            msg = response.json()['message']
            total_nodes = response.json()['total_nodes']
            print(msg)
            for t in total_nodes:
                print(t)

get_id()
send_info()

# 4번 부터 작성