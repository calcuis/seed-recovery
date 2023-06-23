#input seed phrase separated by spaces; i.e., "element entire sniff tired ? solve shadow scatter hello never tank side sight isolate sister uniform advice pen praise soap lizard festival connect baby"
seed_phrase = input("Please input your seed in words (separate by spaces) and leave ? as the missing word(s): ").lower()

import itertools
import hashlib
import requests
from pycoin.symbols.btc import network

def calc_key(seed_phrase , passphrase):
    seed = hashlib.pbkdf2_hmac("sha512",
                                         seed_phrase.encode("utf-8"),
                                         salt=("mnemonic" + passphrase).encode("utf-8"),
                                         iterations=2048,
                                         dklen=64)

    master_key = network.keys.bip32_seed(seed)

    return master_key

def gen_address(derivation_path, master_key):

    subkey = master_key.subkey_for_path(derivation_path)

    hash_160 = subkey.hash160(is_compressed=True)

    if derivation_path[:2] == "49":
        script = network.contract.for_p2pkh_wit(hash_160)
        address = network.address.for_p2s(script)
    elif derivation_path[:2] == "84":
        address = network.address.for_p2pkh_wit(hash_160)
    else:
        address = subkey.address()

    return address

def address_usage(address_list):

    address_url = "https://blockchain.info/balance?active="+"|".join(map("|".join, address_list))

    address_data = requests.get(address_url)
    
    for key,value in address_data.json().items():
        if value['total_received'] > 0:
           address = key
           print("Address: "+ key)
           print("Final Balance: " + str(value["final_balance"]))
           print("Total Recieved: " + str(value["total_received"]))
           print("Number of Tx: " + str(value["n_tx"]))
           break
        else:
            address = ""

    return address
    
def phrase_usage(seed_phrase_list, passphrase = "", derivation_path = ("0/0", "44'/0'/0'/0/0", "49'/0'/0'/0/0", "84'/0'/0'/0/0")):
    max_address_limit = 100

    seed_phrase_limit = max_address_limit//len(derivation_path)

    for i in range(0, len(seed_phrase_list), seed_phrase_limit):
        
        master_keys = [calc_key(seed_phrase, passphrase) for seed_phrase in seed_phrase_list[i:i+seed_phrase_limit]]
        
        addresses = [[gen_address(path, key) for path in derivation_path] for key in master_keys]
        
        address_found = address_usage(addresses)
        
        if address_found != "":
                index_match = [i for i, group in enumerate(addresses)if address_found in group][0]
                print("Seed Phrase: " + seed_phrase_list[i:i+seed_phrase_limit][index_match])
                break

    print("DONE!")

def get_possible(seed_phrase):

    seed_phrase = seed_phrase.split(" ")

    if len(seed_phrase) not in [12, 15, 18, 21, 24]:
        print("Input seed phrase must be 12, 15, 18, 21, or 24 words. Please leave ? for missing word(s).")
        raise SystemExit(0)

    english = open("english.txt")

    word_list = english.read().split("\n")

    english.close()

    seed_phrase_index = [word_list.index(word) if word != "?" else word for word in seed_phrase]

    seed_phrase_binary = [format(number, "011b") if number != "?" else number for number in seed_phrase_index]

    num_missing_bits = int(11-(1/3)*(len(seed_phrase)))

    possible_word_bits = (bin(x)[2:].rjust(11, "0") for x in range(2**11))

    if seed_phrase_binary[-1] != "?":
        missing_bits_possible = (seed_phrase_binary[-1][0:num_missing_bits],)
        checksum = seed_phrase_binary[-1][-(11-num_missing_bits):]
    else:
        missing_bits_possible = (bin(x)[2:].rjust(num_missing_bits, "0") for x in range(2**num_missing_bits))
        checksum = ""

    possible_word_bits_combination = (combination for combination in itertools.product(possible_word_bits,repeat=seed_phrase[:-1].count("?")))

    partial_entropy = ("".join((combination.pop(0) if word == "?" else seed_phrase_local[index] for index,word in enumerate(seed_phrase_local))) if (seed_phrase_local := seed_phrase_binary[:-1]) and (combination := list(word_bits_combination)) else "".join(seed_phrase_local) for word_bits_combination in possible_word_bits_combination)

    entropy_possible = tuple(bit_combination + missing_bits for missing_bits in missing_bits_possible for bit_combination in partial_entropy )

    seed_phrase_binary_possible = (entropy + calc_checksum for entropy in entropy_possible if checksum == (calc_checksum := format(hashlib.sha256(int(entropy, 2).to_bytes(len(entropy) // 8, byteorder="big")).digest()[0],"08b")[:11-num_missing_bits]) or checksum == "")

    seed_phrase_possible = tuple(" ".join([word_list[int(binary[i:i+11],2)] for i in range(0, len(binary), 11)]) for binary in seed_phrase_binary_possible)
    
    return seed_phrase_possible

phrase_usage(get_possible(seed_phrase))