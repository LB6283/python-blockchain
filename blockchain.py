#!/bin/python3
from flask import Flask, render_template, jsonify
from collections import OrderedDict
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import Crypto
import binascii
import uuid
import time
import hashlib
from flask import request
import requests


class Transaction:
    def __init__(self, sender_address, sender_private_key, recipient_address, value, reward):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value
        self.reward = reward
    
    def __getattr__(self, attr):
        return self.data[attr]
    
    def to_dict(self):
        return OrderedDict({"sender_address":self.sender_address,
                            "recipient_address":self.recipient_address,
                            "value":self.value,
                            "reward":self.reward})
    
    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode("utf8"))
        return binascii.hexlify(signer.sign(h)).decode("ascii")

####################################################################################

class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = []
        self.node_id = str(uuid.uuid4()).replace('-', '')
        self.create_block(0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    
    def register_node(self, node_url):
        if node_url not in self.nodes:
            self.nodes.append(node_url)

    def verify_transaction_signature(self, sender_address, signature, transaction):
        public_key = RSA.import_key(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction.to_dict())).encode("utf8")
        return verifier.verify(h, binascii.hexlify(signature))

    def submit_transaction(self, sender_address, recipient_address, value, reward, signature):
        transaction = Transaction(sender_address, None, recipient_address, value, reward)
        if self.verify_transaction_signature(sender_address, signature, transaction):
            self.transactions.append(transaction)

    def create_block(self, nonce, previous_hash):
        block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "transactions": self.transactions,
            "previous_hash": previous_hash,
            "nonce": nonce
        }

    def hash(self, block):
        block_string = str(block).encode("utf8")
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        nonce = 0
        last_hash = self.hash(self.chain[-1])
        while not self.valid_proof(self.transactions, last_hash, nonce):
            nonce += 1
        return nonce

    def valid_proof(self, transactions, last_hash, nonce, difficulty=4):
        guess = f"{str(transactions)}{last_hash}{nonce}".encode("utf8")
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == "0" * difficulty

    def valid_chain(self, chain):
        last_block = chain[0]
        for block in chain:
            if block['previous_hash'] != self.hash(last_block):
                return False
            if not self.valid_proof(block['transactions'], self.hash(last_block), block['nonce']):
                return False
            last_block = block
        return True

    def resolve_conflicts(self):
        longest_chain = None
        max_length = len(self.chain)
        for node in self.nodes:
            try:
                response = requests.get(f"{node}/chain")
                if response.status_code == 200:
                    chain = response.json()["chain"]
                    if len(chain) > max_length and self.valid_chain(chain):
                        max_length = len(chain)
                        longest_chain = chain
            except requests.exceptions.RequestException as e:
                print(f"Error connecting to {node}: {e}")
        if longest_chain:
            self.chain = longest_chain
            return True
        return False

blockchain = Blockchain()

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template("./make_transactions.html")

@app.route("/view/transactions")
def view_transactions():
    return render_template("./view_transactions.html")

@app.route("/wallet/new", methods=["GET"])
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        "private_key":binascii.hexlify(private_key.exportKey(format="DER")).decode("ascii"),
        "public_key":binascii.hexlify(public_key.exportKey(format="DER")).decode("ascii")
    }
    return jsonify(response), 200

@app.route("/generate/transaction", methods=["POST"])
def generate_transaction():
    sender_address = request.form["sender_address"]
    sender_private_key = request.form["sender_private_key"]
    recipient_address = request.form["recipient_address"]
    value = request.form['amount']
    reward = request.form["reward"]

    transaction = Transaction(sender_address, sender_private_key, recipient_address, value, reward)
    response = {
        "transaction": transaction.to_dict(),
        "signature": transaction.sign_transaction()
    } 
    return jsonify(response), 200

@app.route("/chain", methods=["GET"])
def get_chain():
    response = {
        "chain": blockchain.chain,
        "length": len(blockchain.chain)
    }
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)