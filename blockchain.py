import hashlib
import json
import rsa
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from threading import Thread
import signal
from time import sleep


class Blockchain:
    def __init__(self):
        self.leader = ()                    # id : addr pair
        self.leader_idx = -1                # leader's idx
        self.current_transactions = []      # tx
        self.chain = []                     # current chain
        self.nodes = {}                     # connected nodes
        self.status = [None, {}, (0, 0)]    # phase info

        # Generate a globally unique address for this node
        self.node_identifier = str(uuid4()).replace('-', '')

        # Generate a pair of the public key and the private key
        (self.pubkey, self.prikey) = rsa.newkeys(2048)

        # Create the genesis block
        # self.new_block(previous_hash='1', proof=100)

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

    def new_block(self):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
        }

        data = {'block': block, 'phase': 0}

        sign = rsa.sign(str(data).encode('utf8'), self.prikey, 'SHA-1')
        headers = {'Content-Type': 'application/json'}

        for node in self.nodes:
            url = 'http://' + self.nodes[node][0] + '/consensus'                # idx 0 = addr
            cdata = rsa.encrypt(str(data).encode('utf8'), self.nodes[node][1])  # idx 1 = pubkey
            fdata = {'data': list(cdata), 'sign': list(sign), 'id': self.node_identifier}
            jdata = json.dumps(fdata)

            response = requests.post(url, headers=headers, data=jdata)

            if response.status_code == 201:
                print("[PRE PREPARE] ", end="")
                node_id = response.json()['id']
                result = response.json()['result']
                print(node_id, ":", result)

        # delete txs over 2/3
        # # Reset the current list of transactions
        # self.current_transactions = []

        self.status = [block, {}, (0, 0)]

        # append txs over 2/3
        # self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

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