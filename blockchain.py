import hashlib
import json
import rsa
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from ast import literal_eval

import requests
import threading
import signal
from time import sleep

class Blockchain:
    def __init__(self, genesis_block):
        self.heartbeat = -1
        self.lemonbomb = -1                         # thread_id of timer something
        self.is_sexbomb = False                     # global variable for checking consensus
        self.are_sexbomb = False                    # this is what we are going to do now
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
        self.auth = {'address': None, 'pubkey': None}
        self.auth['pubkey'] = rsa.PublicKey(**{'e': 65537, 'n': 17809337809702581702806712750053855729116615216583132187723237673838818997862296690261064757625415664990204748919188173181942765055081418828098039146431896266688540311566257421970474465165733940444107217057017214471218490459283519787553499209929334460323792755288443804920738718853804105499649811677109466929811357788771159957275809186164999242515624152177284219205274328856370640031144310994904160761505104630562313240588506017841870945278152662353349372756482500998680942480381750645179533581431845207703425055137502840627577875951162237565176494850997789361250424373942732156204282322009099409257140674930124768817})

        # Generate a globally unique address for this node
        self.node_identifier = str(uuid4()).replace('-', '')

        # Generate a pair of the public key and the private key
        (self.pubkey, self.prikey) = rsa.newkeys(2048)

        # Create the genesis block
        self.chain.append(genesis_block)

    def register_node(self, node_id, node_addr, node_pubkey):
        """
        Add a new node to the list of nodes

        :param info: Id and address of node.
        Eg. '9b0e332928c24b29962eb4fd4e71af69': 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(node_addr)
        self.nodes[node_id] = (parsed_url.netloc, node_pubkey)


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

        # check either index is right (prevent replay attack)
        block_idx = block.get('index')
        if not self.valid_idx(block_idx):
            self.transactions_buffer += self.current_transactions
            self.current_transactions = []
            return None

        # check the time (prevent DDoS attack)
        block_time = block.get('timestamp')
        if not self.valid_timestamp(block_time):
            self.transactions_buffer += self.current_transactions
            self.current_transactions = []
            return None

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
        self.is_sexbomb = True

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
        self.is_sexbomb = False
        threading.pthread_kill(self.lemonbomb,signal.SIGUSR1)
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
        # TODO: transaction append(After meeting)
        cdata = bytes(fdata['data'])
        sign = bytes(fdata['sign'])

        # Error
        if not rsa.verify(cdata, sign, self.auth['pubkey']):
            pass

        data = rsa.decrypt(cdata, self.prikey)
        data = literal_eval(data.decode('utf8'))
        rand_id = data['rand_id']
        candidate = data['candidate']

        if self.valid_transaction(rand_id):
            self.transactions_buffer.append({
                'sender': rand_id,
                'receiver': candidate
            })
            return True
        else:
            return False

    def valid_transaction(self, rand_id):
        """
        Check it is true that given tx is right

        :param transaction: the given tx
        :return: True or False
        """
        # TODO: transaction check(After meeting)
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
    # TODO: TODODODODODODODODODODODODODODO
    def block_generate(self):
        self.lemonbomb = threading.get_ident()
        n = 0
        while True:
            n += 1
            if n == 7:
                n = 0
                if len(self.transactions_buffer) > 0:
                    self.pre_prepare()
                    signal.pause()
                else:
                    self.heartbeat += 1
                    data = {'heartbeat': self.heartbeat}

                    sign = rsa.sign(str(data).encode('utf8'), self.prikey, 'SHA-1')
                    headers = {'Content-Type': 'application/json'}
                    for node in self.nodes:
                        url = 'http://' + self.nodes[node][0] + '/heartbeat'                # idx 0 = addr
                        cdata = rsa.encrypt(str(data).encode('utf8'), self.nodes[node][1])  # idx 1 = pubkey
                        fdata = {'data': list(cdata), 'sign': list(sign), 'id': self.node_identifier}
                        jdata = json.dumps(fdata)

                        threading.Thread(target=self.block_thread, args=(url, headers, jdata)).start()
            sleep(1)

    def timeout(self):
        self.lemonbomb = threading.get_ident()
        n = 0
        while True:
            if self.are_sexbomb:
                n = 0
                self.are_sexbomb = False
                continue

            if self.is_sexbomb:
                n = 0
                signal.pause()

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

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
         - p is the previous proof, and p' is the new proof
        """

        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Validates the Proof

        :param last_proof: Previous Proof
        :param proof: Current Proof
        :return: True if correct, False if not.
        """

        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


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
