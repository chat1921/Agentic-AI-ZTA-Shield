import datetime
import hashlib
import json
import os

class Blockchain:
    def __init__(self, chain_file='blockchain.json'):
        self.chain_file = chain_file
        self.chain = self.load_chain()
        if not self.chain:
            # Create the genesis block if chain is empty
            self.create_block(proof=1, previous_hash='0', event_type='GENESIS', event_data={'message': 'Genesis Block'})

    def load_chain(self):
        """Loads the blockchain from a file."""
        if os.path.exists(self.chain_file):
            with open(self.chain_file, 'r') as f:
                return json.load(f)
        return []

    def save_chain(self):
        """Saves the blockchain to a file."""
        with open(self.chain_file, 'w') as f:
            json.dump(self.chain, f, indent=4)

    def create_block(self, proof, previous_hash, event_type, event_data):
        """
        Creates a new block and adds it to the chain.
        :param proof: The proof given by the Proof of Work algorithm (simplified for our use).
        :param previous_hash: Hash of the previous Block.
        :param event_type: Type of the event being logged (e.g., 'LOGIN_ATTEMPT').
        :param event_data: A dictionary containing details of the event.
        :return: New Block.
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'event_type': event_type,
            'event_data': event_data
        }
        self.chain.append(block)
        self.save_chain()
        return block

    def get_previous_block(self):
        """Returns the last block in the chain."""
        return self.chain[-1]

    def hash(self, block):
        """
        Creates a SHA-256 hash of a Block.
        :param block: Block dictionary.
        :return: <str> Hash string.
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self):
        """
        Determines if the blockchain is valid by checking hashes.
        :return: <bool> True if valid, False if not.
        """
        previous_block = self.chain[0]
        block_index = 1
        while block_index < len(self.chain):
            block = self.chain[block_index]
            # 1. Check if the previous_hash of the current block is correct
            if block['previous_hash'] != self.hash(previous_block):
                print(f"Chain invalid: Hash mismatch at block {block_index}")
                return False
            
            # (We are omitting a check for 'proof' here to keep it simple and fast)

            previous_block = block
            block_index += 1
        return True