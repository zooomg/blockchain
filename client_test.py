import json
from urllib.parse import urlparse
import requests
import threading
import random
from uuid import uuid4
from flask import Flask, jsonify, request


auth_addr = "http://192.168.0.87:5000"

utxo_msg = {
	"user_mac": "",
	"password": ""
}

tx_msg = {
	"user_mac": "",
	"user_uuid": "",
	"candidate": random.randrange(6)+1,
	"blockchain_name": "bc1"
}

def init_uxto():
	utxo_msg['user_mac'] = str(uuid4()).replace('-', '')
	utxo_msg['password'] = str(uuid4()).replace('-', '')

	headers = {'Content-Type': 'application/json'}
	url = auth_addr + "/user"
	data = json.dumps(utxo_msg)
	
	response = requests.post(url, headers=headers, data=data)
	tx_msg['user_uuid'] = response.json()['Message']
	tx_msg['user_mac'] = utxo_msg['user_mac']
	tx_msg['candidate'] = random.randrange(6)+1;

def init_tx():
	headers = {'Content-Type': 'application/json'}
	url = auth_addr + "/vote"
	data = json.dumps(tx_msg)
	
	response = requests.post(url, headers=headers, data=data)

for i in range(10):
	init_uxto()
	init_tx()