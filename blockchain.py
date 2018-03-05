import hashlib
import json
import rsa
import socket
import netifaces
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from ast import literal_eval

import requests
import threading
import signal
from time import sleep

class Blockchain:
    def __init__(self, port):
        self.addr = "http://" + netifaces.ifaddresses('en0')[netifaces.AF_INET][0]['addr']
        self.port = port

        self.heartbeat = -1
        self.thread_id = -1                         # thread_id of timer something
        self.is_block = False                       # global variable for checking consensus
        self.timer_chk = False                      # this is what we are going to do now
        self.leader = ()                            # id : addr pair
        self.leader_idx = -1                        # leader's idx
        self.transactions_buffer = []               # whole tx
        self.current_transactions = []              # tx of current block
        self.current_block = None                   # current view block
        self.chain = []                             # current chain
        self.nodes = {}                             # connected nodes
        self.status = [0, None, {}, (set(), set())] # phase info [phase_idx, block, {str(block): [list(block's id)]}, (set(yes_id), set(no_id))]
        self.utxo = {}                              # utxo (client_id,checked pair)
        # auth server's (id, pubkey)
        # TODO : Change this
        self.auth = {'address': "http://172.17.65.33:5000", 'pubkey': None}
        # self.auth['pubkey'] = rsa.PublicKey(**{'e': 65537, 'n': 17809337809702581702806712750053855729116615216583132187723237673838818997862296690261064757625415664990204748919188173181942765055081418828098039146431896266688540311566257421970474465165733940444107217057017214471218490459283519787553499209929334460323792755288443804920738718853804105499649811677109466929811357788771159957275809186164999242515624152177284219205274328856370640031144310994904160761505104630562313240588506017841870945278152662353349372756482500998680942480381750645179533581431845207703425055137502840627577875951162237565176494850997789361250424373942732156204282322009099409257140674930124768817})

        # Generate a globally unique address for this node
        self.node_identifier = str(uuid4()).replace('-', '')

        # Generate a pair of the public key and the private key
        (self.pubkey, self.prikey) = rsa.newkeys(2048)
        signal.signal(signal.SIGUSR1,self.anything)

        self.send2auth()

    def send2auth(self):
        """
        Send one's information including bc name, node id, pubkey, ip addr
        """
        print("MY IP : " + self.addr)
        headers = {'Content-Type': 'application/json'}
        url = self.auth['address'] + '/blockchain'

        str_pubkey = str(self.pubkey)
        parse_pubkey = str_pubkey.split('(')[1][:-1].split(' ')
        parse_num = {}
        parse_num['e'] = int(parse_pubkey[1])
        parse_num['n'] = int(parse_pubkey[0][:-1])

        data = {
            'blockchain_id': self.node_identifier,
            'blockchain_name': "sexes",
            'blockchain_pubkey': parse_num,
            'blockchain_ip': self.addr + ":" + self.port
        }

        jdata = json.dumps(data)

        response = requests.post(url, headers=headers, data=jdata)
        if response.status_code == 200:
            print(response.json())
            msg = response.json()['Message']
            self.auth['pubkey'] = rsa.PublicKey(**msg)
        elif response.status_code == 1000:
            print(response.json())
        else:
            print(response.json())

    def anything(self, signum, frame):
        pass

    def register_node(self, node_id, node_addr, node_pubkey):
        """
        Add a new node to the list of nodes

        :param info: Id and address of node.
        Eg. '9b0e332928c24b29962eb4fd4e71af69': 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(node_addr)
        self.nodes[node_id] = (parsed_url.netloc, node_pubkey)

    def append_genesis(self, genesis_block):
        """
        Add the genesis block to the chain
        """
        self.chain.append(genesis_block)

    def consensus_start(self):
        if self.leader[0] == self.node_identifier:
            threading.Thread(target=self.block_generate).start()
        else:
            threading.Thread(target=self.timeout).start()


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours.values():
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    # TODO : make tight of validation
    def valid_block(self):
        """
        Validation of the current block

        :return: str(True) or str(False)
        """

        # if valid node is leader, mu juck gun pass
        if self.node_identifier == self.leader[0]:
            return str(True)

        # check either index is right (prevent replay attack)
        block_idx = self.current_block.get('index')
        if not self.valid_idx(block_idx):
            return str(False)

        # check the time (prevent DDoS attack)
        block_time = self.current_block.get('timestamp')
        if not self.valid_timestamp(block_time):
            return str(False)

        txs = self.current_block.get('transactions')

        # valid whole tx in current block
        # if current tx is valid, pop it from tx buffer
        for tx in txs:
            rand_id = tx.get('sender')
            if rand_id in self.utxo:
                if not self.utxo[rand_id]:
                    self.utxo[rand_id] = True
                    self.current_transactions.append(tx)
                    self.transactions_buffer.remove(tx)
                else:
                    return str(False)
            else:
                return str(False)

        return str(True)

    # TODO : show details; ex) phase #, more response code
    def block_thread(self, url, headers, data):
        """
        Method for threading

        :return: ?
        """
        response = requests.post(url, headers=headers, data=data)

        # if response.status_code == 201:
        #     print("[PRE PREPARE] ", end="")
        #     node_id = response.json()['id']
        #     result = response.json()['result']
        #     print(node_id, ":", result)

    # pre-prepare
    def pre_prepare(self):
        """
        Propose a new block to blockchain network

        :return: new block
        """

        # In fact, it is useless
        if self.leader[0] != self.node_identifier:
            return None

        if len(self.transactions_buffer) > 0:
            self.current_transactions.append(self.transactions_buffer.pop())
        if len(self.transactions_buffer) > 0:
            self.current_transactions.append(self.transactions_buffer.pop())

        print(self.transactions_buffer)

        # TODO : change block params
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
        }

        self.current_block = block

        data = {'block': block, 'phase': 0}

        sign = rsa.sign(str(data).encode('utf8'), self.prikey, 'SHA-1')
        headers = {'Content-Type': 'application/json'}

        for node in self.nodes:
            url = 'http://' + self.nodes[node][0] + '/consensus'                # idx 0 = addr
            print("pre-prepare: from", self.node_identifier, "to", url)
            cdata = rsa.encrypt(str(data).encode('utf8'), self.nodes[node][1])  # idx 1 = pubkey
            fdata = {'data': list(cdata), 'sign': list(sign), 'id': self.node_identifier}
            jdata = json.dumps(fdata)

            threading.Thread(target=self.block_thread, args=(url, headers, jdata)).start()

        self.status = [1, block, {str(block): {self.node_identifier}}, (set(), set())]
        threading.Thread(target=self.prepare).start()

        return block

    def prepare(self):
        """
        Multicast the current view block to others for validation proposal

        :return: block
        """
        data = {'block': self.current_block, 'phase': 1}

        sign = rsa.sign(str(data).encode('utf8'), self.prikey, 'SHA-1')
        headers = {'Content-Type': 'application/json'}

        self.status[2][str(self.current_block)] = {self.leader[0], self.node_identifier}
        self.is_block = True
        sleep(1)

        for node in self.nodes:
            url = 'http://' + self.nodes[node][0] + '/consensus'                # idx 0 = addr
            print("prepare: from", self.node_identifier, "to", url)
            cdata = rsa.encrypt(str(data).encode('utf8'), self.nodes[node][1])  # idx 1 = pubkey
            fdata = {'data': list(cdata), 'sign': list(sign), 'id': self.node_identifier}
            jdata = json.dumps(fdata)

            threading.Thread(target=self.block_thread, args=(url, headers, jdata)).start()

        return self.current_block

    def commit(self):
        """
        Multicast the result of the current node

        :return: result
        """
        result = self.valid_block()

        if result:
            self.status[3][0].add(self.node_identifier)
        else:
            self.status[3][1].add(self.node_identifier)

        data = {'result': result, 'phase': 2, 'index': self.current_block.get('index')}

        sign = rsa.sign(str(data).encode('utf8'), self.prikey, 'SHA-1')
        headers = {'Content-Type': 'application/json'}

        for node in self.nodes:
            url = 'http://' + self.nodes[node][0] + '/consensus'                # idx 0 = addr
            print("commit: from", self.node_identifier, "to", url)
            cdata = rsa.encrypt(str(data).encode('utf8'), self.nodes[node][1])  # idx 1 = pubkey
            fdata = {'data': list(cdata), 'sign': list(sign), 'id': self.node_identifier}
            jdata = json.dumps(fdata)

            threading.Thread(target=self.block_thread, args=(url, headers, jdata)).start()
        self.is_block = False
        print("commit thread_id : " + str(self.thread_id))
        signal.pthread_kill(self.thread_id,signal.SIGUSR1)
        return result

    def add_utxo(self, fdata):
        """
        Creates a new utxo

        :param utxo: Utxo of new client
        """
        # client_id(key) and True or False(value, check he or she complete voting) pair(it will be changed)
        cdata = bytes(fdata['data'])
        sign = bytes(fdata['sign'])

        # Error
        if not rsa.verify(cdata, sign, self.auth['pubkey']):
            pass

        data = rsa.decrypt(cdata, self.prikey)
        data = literal_eval(data.decode('utf8'))
        utxo = data['utxo']

        if not self.exist_utxo(utxo):
            self.utxo[utxo] = False
        else:
            return False

    def exist_utxo(self, utxo):
        if utxo in self.utxo:
            return True
        else:
            return False

    def new_transaction(self, fdata):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param receiver: Address of the Receiver
        :param sign: Sign of Sender
        :return: The index of the Block that will hold this transaction
        """
        # transaction append
        cdata = bytes(fdata['data'])
        sign = bytes(fdata['sign'])

        # Error
        if not rsa.verify(cdata, sign, self.auth['pubkey']):
            pass

        data = rsa.decrypt(cdata, self.prikey)
        data = literal_eval(data.decode('utf8'))
        rand_id = data['rand_id']
        candidate = data['candidate']

        tx = { 'sender': rand_id, 'receiver': candidate }
        if tx in self.transactions_buffer:
            return False

        if self.valid_transaction(rand_id):
            self.transactions_buffer.append(tx)
            return True
        else:
            return False

    def valid_transaction(self, rand_id):
        """
        Check it is true that given tx is right

        :param transaction: the given tx
        :return: True or False
        """
        # transaction check
        if rand_id in self.utxo:
            if not self.utxo[rand_id]:
                return True
            else:
                return False
        else:
            return False

    def valid_idx(self, idx):
        """
        Check it is true that given block's index is right

        :param idx: Index of the given block
        :return: True or False
        """
        if idx == len(self.chain) + 1:
            return True
        else:
            return False

    def valid_timestamp(self, time):
        """
        Check the given block's timestamp to prevent DDoS attack

        :param time: Time of the given block
        :return: True or False
        """
        if time - 5 < self.chain[-1].get('timestamp'):
            return False
        else:
            return True

    def block_generate(self):
        self.thread_id = threading.get_ident()
        print("thread_id : "+str(self.thread_id))
        n = 0
        while True:
            n += 1
            if n == 7:
                n = 0
                if len(self.transactions_buffer) > 0:
                    threading.Thread(target=self.pre_prepare).start()
                    print("[Block Generate] : PAUSE!!!!!!!")
                    signal.pause()
                    print("[Block Generate] : WAKE UP!!!!!!!")
                else:
                    self.heartbeat += 1
                    data = {'heartbeat': self.heartbeat}

                    sign = rsa.sign(str(data).encode('utf8'), self.prikey, 'SHA-1')
                    headers = {'Content-Type': 'application/json'}
                    for node in self.nodes:
                        url = 'http://' + self.nodes[node][0] + '/nodes/leader/heartbeat'                # idx 0 = addr
                        cdata = rsa.encrypt(str(data).encode('utf8'), self.nodes[node][1])  # idx 1 = pubkey
                        fdata = {'data': list(cdata), 'sign': list(sign), 'id': self.node_identifier}
                        jdata = json.dumps(fdata)

                        threading.Thread(target=self.block_thread, args=(url, headers, jdata)).start()
            sleep(1)

    def timeout(self):
        self.thread_id = threading.get_ident()
        n = 0
        while True:
            print("are: "+str(self.timer_chk)+"is: "+str(self.is_block)+"n: "+str(n))
            if self.timer_chk:
                n = 0
                self.heartbeat += 1
                self.timer_chk = False
                continue

            if self.is_block:
                n = 0
                print("[Timeout] : PAUSE!!!!!!!")
                signal.pause()
                print("[Timeout] : WAKE UP!!!!!!!")

            n += 1
            if n == 15:
                n = 0
                print("bomb!!!!!!")

            sleep(1)
        def restart():
            n = 0

    @property
    def last_block(self):
        return self.chain[-1]




# signal ex
# signal.signal(signal.SIGALRM,handler)
# subthread = Thread(target = sub)
# subthread.start()

# Signal Handler
# def handler(signum, frame):
#     print("HI! ALARM"+str(signum))
#
# def sub():
#     while True:
#         signal.alarm(3)
#         sleep(3)
