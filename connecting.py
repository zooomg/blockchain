import json
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request



nodes_addr = ["http://172.17.67.233:5000",   # 권용석
              "http://172.17.64.101:5000"]#,   # 김수형
              # "http://172.17.64.74:5000",    # 주민건
              # "http://172.17.68.65:5000"]    # 정치영

nodes = {}

def get_id():
    for node in nodes_addr:
        url = node + '/id'
        response = requests.get(url=url)
        if response.status_code == 200:
            node_id = response.json()['id']
            nodes[node] = node_id

    print(nodes)

get_id()

# 4번 부터 작성
