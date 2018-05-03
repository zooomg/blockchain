import json
from urllib.parse import urlparse
import requests
import threading
from uuid import uuid4
from flask import Flask, jsonify, request


auth_addr = "http://172.17.68.3:3000"
query = {
	"ts_from": '2018-04-12 18:30:06',
	"ts_to": '2018-04-12 18:30:08'
}

def select_data():
	headers = {'Content-Type': 'application/json'}
	url = auth_addr + "/log_timestamp"
	data = json.dumps(query)
	
	response = requests.post(url, headers=headers, data=data)
	print(response.json()['Message'])
	print(response.json()['Data'])

select_data()