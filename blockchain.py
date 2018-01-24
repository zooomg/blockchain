import hashlib
import json
import rsa
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
import threading
import signal
from time import sleep

class Blockchain:
    def __init__(self, genesis_block):
        self.leader = ()                            # id : addr pair
        self.leader_idx = -1                        # leader's idx
        self.transactions_buffer = []               # whole tx
        self.current_transactions = []              # tx of current block
        self.current_block = None                   # current view block
        self.chain = []                             # current chain
        self.nodes = {}                             # connected nodes
        self.status = [0, None, {}, (set(), set())] # phase info [phase_idx, block, {str(block): [list(block's id)]}, (set(yes_id), set(no_id))]

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

        self.current_transactions = self.transactions_buffer
        for tx in self.current_transactions:
            if tx in self.transactions_buffer:
                self.transactions_buffer.remove(tx)

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

        return result

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.transactions_buffer.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

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
