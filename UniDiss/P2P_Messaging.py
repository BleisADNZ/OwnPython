import socket
import threading
from threading import *
import json
import rsa
import random
import os
import time
import datetime
from datetime import timedelta

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

serverPort = 8000

log = []

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

################################################################# The encryption and the beratnas



def raw_input(text):
    try:
        return raw_input(text)
    except:
        return input(text)



spacer = "\n================\n\n"

print(spacer + "Loading keys...")

fileContent = ''

#the_public_key
#the_private_key
#username
#userId
#userId_hash
#userId_signature
#user_host
#fernetKey
#user_key

try:
    #================ Main files to import ============================================================================================ Loading dock
    #userentry

    file = open('salt', 'rb')
    user_key = rsa.compute_hash(raw_input(spacer + "Type the key to decrypt your files? => ").encode('utf8'), 'SHA-1') # ==================================== User Key
    
    if file.mode == 'rb':
        salt_recovered = file.read()
        file.close()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_recovered,
            iterations=100000,
            backend=default_backend()
        )
    
    fernetKey = base64.urlsafe_b64encode(kdf.derive(user_key))
    


    # ======================================================================= fernetKey
    
    #userblocks
    file = open('userblocks', 'rb')
    if file.mode == 'rb':
        fileContent = file.read() # Loading content
        file.close()

        f = Fernet(fernetKey)
        json_fileContent = json.loads(f.decrypt(fileContent).decode('utf8')) 
        # ======================================================================= json_fileContent
        user_private_key = rsa.PrivateKey(json_fileContent["users"][0]["publickey"]["n"], json_fileContent["users"][0]["publickey"]["e"], json_fileContent["users"][0]["privatekey"]["d"], json_fileContent["users"][0]["privatekey"]["p"], json_fileContent["users"][0]["privatekey"]["q"])
        
        print(spacer + "Welcome " + json_fileContent["users"][0]["user"])
     # To send them to create character
    #userchatlogs
    file = open('chatblocks', 'rb')
    if file.mode == 'rb':
        chatLogContent = file.read()
        file.close()

        f = Fernet(fernetKey)
        json_chatLogContent = json.loads(f.decrypt(chatLogContent).decode('utf8'))
        # ======================================================================= json_fileContent
        
        print("Chat blocks loaded.")
    # To send them to create character
    
    file = open('comms', 'rb')
    if file.mode == 'rb':
        commContent = file.read()
        file.close()

        f = Fernet(fernetKey)
        communications = json.loads(f.decrypt(commContent).decode('utf8'))
        # ======================================================================= communications
        
        print("Communications loaded.")
        
        print("\nType 'help' to show more commands.")
        
    #================================================================================================================================== Loading dock
except:
    print("\nUser files not found.")
    print(spacer + "Generating keys...\nThis may take 1-2 minutes as the keys are 4096 bit long...")
    (the_public_key, the_private_key) = rsa.newkeys(4096) # Generating new RSA keys
    print("The keys have been created.")
    isAllowedToBeAName = False
    while isAllowedToBeAName == False: # Verify user name is valid
        username = raw_input(spacer + "What would your username be? (it will be used on USERID and it cannot be changed)\n=> ") # Username#
        if username.isalpha() and len(username) <= 490: # By comparing whether is less than 490 character or that is only letters
            isAllowedToBeAName = True
        elif len(username) > 490:
            print("The username can only contain less than 490 characters\n") # This is just to secure the ability to encrypt userIds with 4096 bit keys,
                                                                              # as another 11 characters will be added
        else:
            print("The username can only contain letters\n")

    userId = username + "#"
    print("\nAdding a # to the user ID")
    string_public_key = str(the_public_key.n)
    for x in range(10):
        userId = userId + string_public_key[random.randint(0, len(string_public_key) - 1)]
    print("User ID created > " + userId)


    #============================================================= User ID#


    
    userId_hash = rsa.compute_hash(userId.encode('utf8'), 'SHA-1')
    userId_signature = rsa.sign_hash(userId_hash, the_private_key, 'SHA-1') # ========================= User ID Signature#
    print("Signing user ID to link both the user name and keys")
    user_host = get_ip()
    print("Getting connexion details")



    print("Creating user blocks")

    json_fileContent = {}
    json_fileContent['users'] = []
    json_user = {}
    json_user['user'] = username
    json_user['userid'] = userId
    json_user['signature'] = base64.b64encode(userId_signature).decode('utf8')
    json_user['publickey'] = {}
    json_user['publickey']['n'] = the_public_key.n
    json_user['publickey']['e'] = the_public_key.e
    json_user['privatekey'] = {}
    json_user['privatekey']['d'] = the_private_key.d
    json_user['privatekey']['p'] = the_private_key.p
    json_user['privatekey']['q'] = the_private_key.q
    json_user['ip'] = user_host
    json_user['truCon'] = []

    json_fileContent['users'].append(json_user)
    
    
    user_private_key = rsa.PrivateKey(json_fileContent["users"][0]["publickey"]["n"], json_fileContent["users"][0]["publickey"]["e"], json_fileContent["users"][0]["privatekey"]["d"], json_fileContent["users"][0]["privatekey"]["p"], json_fileContent["users"][0]["privatekey"]["q"])
    
    print("Creating chat blocks")
    chatLogContent = '{"chats":[]}'
    

    json_chatLogContent = json.loads(chatLogContent) # ======================================================= The json for chats


    communications = {}
    communications["request"] = [] # Friend requests
    communications["chats"] = [] # Messages too friends
    communications["pchats"] = [] # private messages to send through trusted users
    communications["sentToPChats"] = [] # a variable to record who received messages to stop sending messages
    communications["missing"] = [] # if messages are missing between messages sent
    communications["cttUpdate"] = True # Variable to check whether all personal contacts know you trusted list
    communications["cttWhoUpdated"] = [] # Array of contacts that updated your trusted list


    # ======================================================= The json for comms



    user_key = rsa.compute_hash(raw_input(spacer + "To save the data a key is needed to encrypt the data" +
                                          "\nType a key (it can be anything)? => ").encode('utf8'), 'SHA-1') # User Key

    salt = os.urandom(16) # Generate random 16bit value

    print(spacer + "A file called 'salt' will be created, this file is needed for future access")
    file = open('salt', 'wb')
    file.write(salt) # Salt being saved for future use
    file.close()

    kdf = PBKDF2HMAC( 
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt, # Salt added to the function to use it to generate keys
        iterations=100000,
        backend=default_backend()
    )
    
    fernetKey = base64.urlsafe_b64encode(kdf.derive(user_key)) # Generate key out of user key input

    

    print(spacer + "The key has been created.")

    f = Fernet(fernetKey)
    fileContent = f.encrypt(json.dumps(json_fileContent).encode('utf8'))
    # Encrypt content
    file = open('userblocks', 'wb')
    file.write(fileContent) # Save Content
    file.close()
    
    chatLogContent = f.encrypt(chatLogContent.encode('utf8'))
    
    file = open('chatblocks', 'wb')
    file.write(chatLogContent)
    file.close()
    
    commsFileContent = f.encrypt(json.dumps(communications).encode('utf8'))
    
    file = open('comms', 'wb')
    file.write(commsFileContent)
    file.close()  
    print("\nType 'help' to show more commands.")









################################################################# The connexion


serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = get_ip()
port = 8000
#print (spacer + "Your message receiver address\n")

my_host_name = (host, port)
serversocket.bind(my_host_name)

addressesFromAll = []
chatlogs = []
run_the_server = True

class client(Thread):

    
    
    def __init__(self, socket, address):
        Thread.__init__(self)
        global addressesFromAll
        addressesFromAll.append(address)
        self.sock = socket
        self.addr = address
        self.allowed = 1 
        self.chat = 0
        self.current_message = {}
        self.chatlog = []
        self.receiver_mode = 0
        self.how_many_to_receive = 0
        self.full_msg = []
        self.start()
        logm(str(address) + " connected")
        

    def run(self):
        try:
            while self.allowed > 0: # The first message is authenticating the user
                global chatlogs
                #logm(str(self.receiver_mode))
                recv_msg = self.sock.recv(4096) # ============================== For the user to use the next few functions to receive it needs a verification
                if recv_msg != '':
                    recv_msg = recv_msg
                    

                    try:
                        recv_msg = recv_msg.decode('utf8')
                        if recv_msg[:3] == 'who' and self.receiver_mode == 0: #the above code does the same, but this is simple
                            full_msg_str = ''
                            self.how_many_to_receive = int(recv_msg[3:])
                            logm(str(self.addr) + " sent a 'who' with " + recv_msg[3:])
                            self.receiver_mode = 1
                        elif self.receiver_mode == 1: # everyone gets a single msg, if i know you 
                            if self.how_many_to_receive > 0:
                                full_msg_str = full_msg_str + recv_msg
                                self.how_many_to_receive = self.how_many_to_receive - 1
                            if self.how_many_to_receive == 0:
                                #logm(full_msg_str)
                                (self.allowed, self.receiver_mode, self.chat) = authenticate(full_msg_str, self.allowed, self.addr) # During the authentication, it should give the server if the connection can get more msgs
                                msg_hash_ver = rsa.compute_hash(full_msg_str.encode('utf8'), 'SHA-1')
                                logm(str(self.addr) + " verifiying message")
                                self.sock.send(msg_hash_ver) # << the reason as to why not signing is because in this process the users dont know eah others public keys
                                # if the user is not known the receiver just stop receiving any data
                        elif recv_msg[:3] == 'ctt' and self.receiver_mode == 0:
                            self.full_msg = []
                            self.how_many_to_receive = int(recv_msg[3:])

                            logm(str(self.addr) + " sent a 'ctt' with " + recv_msg[3:])
                            
                            self.current_message['userid'] = self.sock.recv(4096)
                            self.current_message['signature'] = self.sock.recv(4096)
                            
                            verified, self.chat, pubkey = trust_check_auth(self.current_message['userid'], self.current_message['signature'])
                            if (verified):
                                self.sock.send(rsa.encrypt(json_fileContent['users'][0]['userid'].encode('utf8'), pubkey))
                                time.sleep(1)
                                self.sock.send(rsa.sign_hash(rsa.compute_hash(json_fileContent['users'][0]['userid'].encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1'))
                                self.receiver_mode = 3
                        elif recv_msg[:3] == 'pch' and self.receiver_mode == 0:
                            logm(str(self.addr) + " sent a 'pch' with " + recv_msg[3:])
                            self.full_msg = []
                            self.how_many_to_receive = int(recv_msg[3:])
                            
                            self.current_message['userid'] = self.sock.recv(4096)
                            self.current_message['signature'] = self.sock.recv(4096)
                            logm("Received data")
                            (verified, self.current_message['trustedCoordinates'], pubkey) = trusted_check_auth(self.current_message['userid'], self.current_message['signature'])
                            logm("Auth taken")
                            if (verified):
                                
                                logm("Verified data")
                                self.sock.send(rsa.encrypt(json_fileContent['users'][0]['userid'].encode('utf8'), pubkey))
                                time.sleep(1)
                                self.sock.send(rsa.sign_hash(rsa.compute_hash(json_fileContent['users'][0]['userid'].encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1'))

                                self.receiver_mode = 4
                        elif recv_msg[:3] == 'pos' and self.receiver_mode == 0:
                            self.full_msg = []
                            self.how_many_to_receive = int(recv_msg[3:])
                            logm(str(self.addr) + " sent a 'pos' with " + recv_msg[3:])
                            
                            self.current_message['userid'] = self.sock.recv(4096)
                            self.current_message['signature'] = self.sock.recv(4096)
                            
                            verified, self.chat, pubkey = trust_check_auth(self.current_message['userid'], self.current_message['signature'])
                            if (verified):
                                self.sock.send(rsa.encrypt(json_fileContent['users'][0]['userid'].encode('utf8'), pubkey))
                                time.sleep(1)
                                self.sock.send(rsa.sign_hash(rsa.compute_hash(json_fileContent['users'][0]['userid'].encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1'))

                                self.receiver_mode = 5
                    except Exception as e:
                        #logm("'' the quotes")
                        #logm(e)
                        if self.receiver_mode == 3:
                            logm("Receiving CTT")
                            if self.how_many_to_receive > 0:
                                self.full_msg.append(recv_msg)
                                self.how_many_to_receive = self.how_many_to_receive - 1
                            if self.how_many_to_receive == 0:
                                self.current_message['signature'] = self.sock.recv(4096)
                                self.current_message['ctt'] = ''
                                for each in self.full_msg:
                                    self.current_message['ctt'] = self.current_message['ctt'] + rsa.decrypt(each, user_private_key).decode('utf8')

                                    
                                if rsa.verify(self.current_message['ctt'].encode('utf8'), self.current_message['signature'], rsa.PublicKey(json_fileContent["users"][self.chat]["publickey"]["n"], json_fileContent["users"][self.chat]["publickey"]["e"])): 
                                    
                                    add_ctt(self.current_message['ctt'], self.chat)
                                    msg_sign_ver = rsa.sign_hash(rsa.compute_hash(self.current_message['ctt'].encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1')
                                    self.sock.send(msg_sign_ver) # Letting the sender know we received it
                                self.receiver_mode = 0
                                #This is to receive dht tables from users

                        
                        elif self.receiver_mode == 4:
                            logm("Receiving PCH")
                            if self.how_many_to_receive > 0:
                                self.full_msg.append(recv_msg)
                                self.how_many_to_receive = self.how_many_to_receive - 1
                            if self.how_many_to_receive == 0:
                                # Deal with the array
                                current_pchat = ''
                                current_signature = self.sock.recv(4096)
                                for each in self.full_msg:
                                    current_pchat = current_pchat + rsa.decrypt(each, user_private_key).decode('utf8')
                                    
                                if rsa.verify(current_pchat.encode('utf8'), current_signature, rsa.PublicKey(
                                               json_fileContent["users"][self.current_message['trustedCoordinates'][0]]["trusted"][self.current_message['trustedCoordinates'][1]]['publickey']['n'],
                                               json_fileContent["users"][self.current_message['trustedCoordinates'][0]]["trusted"][self.current_message['trustedCoordinates'][1]]['publickey']['e'])): 
                                    
                                    # Add it
                                    add_pchat(current_pchat)
                                    msg_sign_ver = rsa.sign_hash(rsa.compute_hash(current_pchat.encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1')
                                    self.sock.send(msg_sign_ver) # Letting the sender know we received it
                                self.receiver_mode = 0
                                
                        
                        elif self.receiver_mode == 5:
                            logm("Receiving POS")
                            if self.how_many_to_receive > 0:
                                self.full_msg.append(recv_msg)
                                self.how_many_to_receive = self.how_many_to_receive - 1
                            if self.how_many_to_receive == 0:
                                # Deal with the array
                                current_poschat = ''
                                current_signature = self.sock.recv(4096)
                                for each in self.full_msg:
                                    current_poschat = current_poschat + rsa.decrypt(each, user_private_key).decode('utf8')
                                #logm(current_poschat)
                                if rsa.verify(current_poschat.encode('utf8'), current_signature, rsa.PublicKey(
                                               json_fileContent["users"][self.chat]['publickey']['n'],
                                               json_fileContent["users"][self.chat]['publickey']['e'])): 
                                    
                                    # Add it
                                    add_poschat(current_poschat)
                                    msg_sign_ver = rsa.sign_hash(rsa.compute_hash(current_poschat.encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1')
                                    self.sock.send(msg_sign_ver) # Letting the sender know we received it
                                self.receiver_mode = 0

                    
                        
                    
                    
        except Exception as e:
            logm("run(self)")
            logm(e)

    def showName(self):
        print(self.addr)
    def showChat(self):
        print("======================================================",self.chatlog,"======================================================")



def trusted_check_auth(userid, signature): # Authenticate trusted contacts list users
    var_if = False
    var_x = 0
    var_y = 0
    useridDecrypted = rsa.decrypt(userid, user_private_key).decode('utf8')
    logm("Verify " + useridDecrypted)
    for each in range(len(json_fileContent['users'])-1):
        for eachTrusted in range(len(json_fileContent['users'][each+1]['trusted'])):
            if (useridDecrypted == json_fileContent['users'][each+1]['trusted'][eachTrusted]['userid']):
                var_x = each+1
                var_y = eachTrusted
                break
                
    
    var_pubkey = rsa.PublicKey(json_fileContent["users"][var_x]["trusted"][var_y]['publickey']['n'],json_fileContent["users"][var_x]["trusted"][var_y]['publickey']['e'])

    var_verified = rsa.verify(useridDecrypted.encode('utf8'), signature, var_pubkey)
        
    return (var_verified, (var_x, var_y), var_pubkey)


def trust_check_auth(userid, signature): # Authenticate trusted users
    var_if = False
    var_x = 0
    useridDecrypted = rsa.decrypt(userid, user_private_key).decode('utf8')
    for each in range(len(json_fileContent['users'])-1):
        if (useridDecrypted == json_fileContent['users'][each+1]['userid'] and json_fileContent['users'][each+1]['trust'] >= 2):
            var_x = each+1
            var_if = True
            break

    var_pubkey = rsa.PublicKey(json_fileContent["users"][var_x]['publickey']['n'],json_fileContent["users"][var_x]['publickey']['e'])

    var_verified = rsa.verify(useridDecrypted.encode('utf8'), signature, var_pubkey)
        
    
    return (var_verified, var_x, var_pubkey)


def authenticate(who, allowed, address): # Method to authenticate users from "who" requests
    try:
        #logm("User trying to authenticate from " + str(address))
        do_i_know_you = False
        if_do_index = 0
        
        time.sleep(1)
        json_who = json.loads(who)
        for x in range(len(json_fileContent["users"])-1):
            if (json_fileContent["users"][x+1]["userid"] == json_who["userid"]):
                if_do_index = x+1
                do_i_know_you = True

        # Authentication 
        # First, for every time a 'who' msg comes through, the user is going to be checked
        # ^^^Above we try finding the user on our database
        # below, if we know them, check for trust level
        # 0 = you sent the request, to receive their details and set the trust to 2
        # 1 = they sent the request, for you to send the request back then set the trust to 2
        # 2 = full contact member, automatic authentication and set to receive messages and send, 'who', 'cha', 'sig'

            
        if do_i_know_you: # if the user is on the data base
            if json_fileContent["users"][if_do_index]["trust"] == 0: # Use the trust score on the user, "0" being to not receive any msgs from the connection
                
                if (rsa.verify(json_who["userid"].encode('utf8'), base64.b64decode(json_who["signature"].encode('utf8')), rsa.PublicKey(json_who["publickey"]["n"], json_who["publickey"]["e"]))):
                    json_fileContent["users"][if_do_index]["user"] = json_who["user"]
                    json_fileContent["users"][if_do_index]["userid"] = json_who["userid"]
                    json_fileContent["users"][if_do_index]["publickey"] = {}
                    json_fileContent["users"][if_do_index]["publickey"]["n"] = json_who["publickey"]["n"]
                    json_fileContent["users"][if_do_index]["publickey"]["e"] = json_who["publickey"]["e"]
                    json_fileContent["users"][if_do_index]["address"] = address[0]
                    json_fileContent["users"][if_do_index]["trust"] =  2
                    json_fileContent["users"][if_do_index]["trusted"] =  []
                    
                    communications["cttUpdate"] = True

                    # Creating chat block for the user
                    newUserChatBlock = {}
                    newUserChatBlock["userid"] = json_who["userid"]
                    newUserChatBlock["hashesFrom"] = []
                    
                    newUserChatBlock["hashesFrom"].append(base64.b64encode(rsa.compute_hash(json_fileContent["users"][0]["userid"].encode('utf8'), 'SHA-1')).decode('utf8'))
                    newUserChatBlock["logFrom"] = []
                    newUserChatBlock["hashesTo"] = []
                    newUserChatBlock["hashesTo"].append(base64.b64encode(rsa.compute_hash(json_who["userid"].encode('utf8'), 'SHA-1')).decode('utf8'))
                    newUserChatBlock["logTo"] = []
                    json_chatLogContent["chats"].append(newUserChatBlock)
                #===========================================================================================================
                logm("You and " + json_who["userid"] + " are friends")
                return (allowed+1, 0, if_do_index)
            elif json_fileContent["users"][if_do_index]["trust"] > 1: # if their trust score is higher they are allowed to msg
                return (allowed+1, 2, if_do_index)
        else:
            # if the person is not on the userblock
            # return that they cannot send another msg, as they already send their dets, it acts as a friend request
            if (rsa.verify(json_who["userid"].encode('utf8'), base64.b64decode(json_who["signature"].encode('utf8')), rsa.PublicKey(json_who["publickey"]["n"], json_who["publickey"]["e"]))):
                json_who["address"] = address[0]
                json_who["trust"] =  1 # Of course, verify the details so they are valid and signed, and add the trust score, at 1 
                json_fileContent["users"].append(json_who)
                logm("You and just received a request from " + str(address))
                #print(json_who["userid"] + "has s")
            return (allowed+1, 0, len(json_fileContent["users"])-1)

    except Exception as e:
        
        logm("authenticate(who, allowed, address)")
        logm(e)
        return (allowed+1, 0, 0)

def receive_the_chat(chatblock, chathash): # Receiver of any chat blocks
    # verify the chat block
    logm("Receiving Message")
    try:
        
        chatBlockCursor = 0
        json_chatblock = json.loads(chatblock.replace("'", "\""))
        for each in json_chatLogContent['chats']:
            if each['userid'] != json_chatblock["userid"]:
                chatBlockCursor = chatBlockCursor + 1
            else:
                break

        
        message_chain_hash = rsa.compute_hash((
                                json_chatLogContent['chats'][chatBlockCursor]['hashesFrom']
                                [len(json_chatLogContent['chats'][chatBlockCursor]['hashesFrom'])-1]
                                +json.dumps(json_chatblock)).encode('utf8'), 'SHA-1')
        logm(json_chatLogContent['chats'][chatBlockCursor]['hashesFrom']
                                [len(json_chatLogContent['chats'][chatBlockCursor]['hashesFrom'])-1] + "\nMessage chain hash " + base64.b64encode(message_chain_hash).decode('utf8'))
                        
        
        if (message_chain_hash == chathash): # Then add it if the hashes match
            json_chatLogContent['chats'][chatBlockCursor]['hashesFrom'].append(base64.b64encode(message_chain_hash).decode('utf8')) # It saves, but only if the coditions are met
            json_chatLogContent['chats'][chatBlockCursor]['logFrom'].append(json_chatblock)
        else:
            # Check if not identified, its old or not
            if chathash not in json_chatLogContent['chats'][chatBlockCursor]['hashesFrom']:
                missingBlock = {}
                missingBlock["userid"] = json_chatLogContent['chats'][chatBlockCursor]['userid']
                missingBlock["last_hash"] = json_chatLogContent['chats'][chatBlockCursor]['hashesFrom'][len(json_chatLogContent['chats'][chatBlockCursor]['hashesFrom'])-1] # Recording the last hash and the new one to find missing
                communications["missing"].append(missingBlock)
    except Exception as e:
        logm("receive_the_chat(chatblock, chathash)")
        logm(e)
    return

def add_ctt(ctt, current_contact):# Receiver of any "ctt" packets
    ## Adding ctt to
    json_ctt = json.loads(base64.b64decode(ctt.encode('utf8')).decode("utf8").replace("'", "\""))
    json_fileContent['users'][current_contact]['trusted'] = json_ctt
    logm(json_fileContent['users'][current_contact]['userid'] + "'s trusted table updated")
    return

def add_pchat(pchat):# Receiver of any "pch" packets
    ## Adding ctt to
    json_pchat = json.loads(pchat.replace("'", "\""))
    if json_pchat not in communications['pchats']:
        json_pchat['time'] = (datetime.datetime.now() + timedelta(days=1)).strftime("%Y%m%d%H%M%S")
        communications['pchats'].appends(json_pchat)
        logm("pChat received and added")
    return

def add_poschat(pchat):# Receiver of any "pos" packets
    ## Adding ctt to
    try:
        
        logm("pChat 'pos' received")
        json_pchat = json.loads(pchat.replace("'", "\""))
        contact_no = 0
        contact_no_chat = 0
        message = ''

        if json_pchat['type'] == 0:
            for each in range(len(json_fileContent['users'])-1):
                if json_pchat['from'] == json_fileContent['users'][each+1]['userid']:
                    contact_no = each+1
                    break
            for each in range(len(json_chatLogContent['chats'])):
                if json_pchat['from'] == json_chatLogContent['chats'][each]['userid']:
                    contact_no_chat = each
                    break
            if contact_no != 0:
                for each in json_pchat['chat']['chat']:
                    message = message + rsa.decrypt(base64.b64decode(each.encode('utf8')), user_private_key).decode('utf8')
                if rsa.verify(message.encode('utf8'), base64.b64decode(json_pchat['chat']['signature'].encode('utf8')), rsa.PublicKey(json_fileContent['users'][contact_no]['publickey']['n'], json_fileContent['users'][contact_no]['publickey']['e'])):
                    logm("Message chain hash " + json_pchat['chat']['hash'])
                    receive_the_chat(message, base64.b64decode(json_pchat['chat']['hash'].encode('utf8')))
        else:
            for each in range(len(json_fileContent['users'])-1):
                if json_pchat['from'] == json_fileContent['users'][each+1]['userid']:
                    contact_no = each+1
                    break
            if contact_no != 0:
                for each in json_pchat['chat']['msg']:
                    message = message + rsa.decrypt(base64.b64decode(each.encode('utf8')), user_private_key).decode('utf8')
                if rsa.verify(message.encode('utf8'), base64.b64decode(json_pchat['chat']['signature'].encode('utf8')), rsa.PublicKey(json_fileContent['users'][contact_no]['publickey']['n'], json_fileContent['users'][contact_no]['publickey']['e'])):
                    logm("Missing report received")
                    add_missing_report(message, contact_no)
            
    except Exception as e:
        logm("add_poschat(pchat)")
        logm(e)
    

def add_missing_report(json_data, user_index): # Add missing reports, which happens if unknown messages have been received and dont match with the chain
    try:
        logm("Missing report received")
        json_report = json.loads(json_data.replace("'", "\""))

        for each in range(len(json_chatLogContent['chats'])):
            if json_fileContent['users'][user_index]["userid"] == json_chatLogContent['chats'][each]['userid']:
                contact_no_chat = each
                break

        ready_to_send = False
        for each in range(len(json_chatLogContent['chats'][contact_no_chat]['hashesTo'])-1):
            if json_report['last_hash'] == json_chatLogContent['chats'][contact_no_chat]['hashesTo'][each+1]:
                ready_to_send = True
            if ready_to_send:
                pchat_block = {}
                pchat_block['type'] = 0
                pchat_block['from'] = json_fileContent['users'][0]['userid']
                pchat_block['to'] = json_fileContent['users'][user_index]['userid']
                pchat_block['chat'] = {}
                pchat_block['chat']['chat'] = json_chatLogContent['chats'][contact_no_chat]['logTo'][each]['chat']
                pchat_block['chat']['hash'] = json_chatLogContent['chats'][contact_no_chat]['logTo'][each]['hash']
                pchat_block['chat']['signature'] = json_chatLogContent['chats'][contact_no_chat]['logTo'][each]['signature']
                
                pchat_sent_to = {}
                pchat_sent_to['pchatHash'] = base64.b64encode(rsa.compute_hash(str(pchat_block).encode('utf8'), 'SHA-1')).decode('utf8')
                pchat_sent_to['sent_to'] = []
                
                communications['sentToPChats'].append(pchat_sent_to)
                communications['pchats'].append(pchat_block)

        # ============================================================================================================================================
    except Exception as e:
        logm("add_missing_report(json_data, user_index)")
        logm(e)

def run_the_server(): # Run the server method
    serversocket.listen(5)
    global run_the_server
    while run_the_server:
        clientsocket, address = serversocket.accept()
        client(clientsocket, address)

def run_in_the_background(): # Method to set all the threads in motion
    global the_background_server
    global the_background_communicator
    
    the_background_server.start()
    the_background_communicator.start()
    
    
def dont_run_in_the_background(): # Fucntion to disable the servers and threads
    global the_background_server
    global the_background_communicator
    global run_the_server
    run_the_server = False
    


################################################################# The menu

def run_the_main(): # Main menu that handles user input
    while 1:
        menu_cursor = "0"
        if menu_cursor == "0":
            menu_cursor = raw_input(spacer + "Main Menu\n\n=> ")
        if menu_cursor == "chat":
            see_chats()
            menu_cursor = "0"
        if menu_cursor == "send":
            send_msg()
            menu_cursor = "0"
        if menu_cursor == "profile":
            show_profile()
            menu_cursor = "0"
        if menu_cursor == "trusted":
            show_trusted()
            menu_cursor = "0"
        if menu_cursor == "addcon":
            send_request()
            menu_cursor = "0"
        if menu_cursor == "showcon":
            see_request()
            menu_cursor = "0"
        if menu_cursor == "comm":
            see_comms()
            menu_cursor = "0"
        if menu_cursor == "show":
            show_contacts()
            menu_cursor = "0"
        if menu_cursor == "log":
            see_log()
            menu_cursor = "0"
        if menu_cursor == "help":
            see_help()
            menu_cursor = "0"
        if menu_cursor == "update ctt":
            updateCtt()
            menu_cursor = "0"
        if menu_cursor == "exit":
            dont_run_in_the_background()
            exit()


################################################################# The menu functions

def see_help(): # Method to show command instructions to the user
    print(spacer + "'chat' - show chats"+
          "\n\n'show' - show contacts"+
          "\n\n'send' - send message"+
          "\n\n'addcon' - add contact"+
          "\n\n'log' - to open log from last 30 logs"+
          "\n\n'showcon' - show contact requests in/out"+
          "\n\n'comm' - show communicator database lengths"+
          "\n\n'exit' - exit application(still working process...)"+
          "\n\n'help' - show this help guide")
    raw_input("")
    
def updateCtt(): # Method to update this certain variable to, if its true it will sent the users ctt to all of his users
    communications["cttUpdate"] = True
    

def see_log(): # Method to see the last 30 log messages from the application
    print(spacer)
    if len(log) > 31:
        for x in range(30):
            print(log[(len(log)-31)+x])
    else:
        for x in log:
            print(x)
    
    raw_input("")

def see_comms(): # Show communication processes being processed
    print(spacer + "There are:\nRequests:", len(communications["request"]))
    print("Chats:", len(communications["chats"]))
    print("PChats:", len(communications["pchats"]))
    print("SentToPChats:", len(communications["sentToPChats"]))
    print("Missing:", len(communications["missing"]))
    print("CttUpdate:", communications["cttUpdate"])
    print("CttWhoUpdated: " + str(len(communications["cttWhoUpdated"])) + "/" + str(len(json_fileContent['users'])-1))
    
def show_profile(): # Method to show and let the user know how to open ports as well as how to share the user id and tag
    print(spacer)
    print("Once ports are forwarded to " + host + " on port 8000\nadd your public IP address behind '@' on your user name\n\n")
    print(json_fileContent['users'][0]['userid'] + "@")
    print("\neg. \nexample#0123456789@10.20.30.40\n\nOnce the address is completed, share the address to allow users connect")
    raw_input("")

def show_contacts(): # Method to print out all the contacts 
    print(spacer)
    for user_index in range(len(json_fileContent['users'])-1):
        user_block = json_fileContent['users'][user_index+1]
        print(user_block['userid'] + " - trust - " + str(user_block['trust']))

def see_chats(): # Method to see the messages from contacts


    questions = ["Who's chat do you want to open?", "Which chat?"]
    got_a_name = False
    while got_a_name == False:
        print(spacer + questions[random.randint(0, len(questions)-1)])
        index = 0
        try:
            for x in range(len(json_fileContent["users"])-1):
                if json_fileContent["users"][x+1]["trust"] > 0:
                    print("\n("+str(x+1)+") " + json_fileContent["users"][x+1]["userid"])

            answer = int(raw_input("\n=> "))
            # verify
            user_chat_cursor = 0
            for cursor in range(len(json_chatLogContent['chats'])-1):
                if json_chatLogContent['chats'][cursor+1]['userid'] == json_fileContent["users"][answer]["userid"]:
                    user_chat_cursor = cursor+1
            all_messages = []
            for cursor in json_chatLogContent['chats'][user_chat_cursor]['logFrom']:
                all_messages.append(cursor)
            for cursor in json_chatLogContent['chats'][user_chat_cursor]['logTo']:
                all_messages.append(cursor)
            all_messages.sort(key=extract_time)
            print('\n\n')
            for chat in all_messages:
                print(chat['userid'] + "  -  " + chat['msg'])
            print('\n\n')
        except Exception as e:
            logm("see_chats()")
            logm(e)
        got_a_name = True
    return

def extract_time(json): # Method to extract the time from json values, this is used to align the chat from top to bottom or bottom to top
    try:
        return int(json['time'])
    except KeyError:
        return 0

def see_request(): # Method to print out requests
    try:
        print(spacer + "You have sent requests to:\n")
        next_list = ""
        list_of_users = []
        for x in range(len(json_fileContent["users"])-1):
            if json_fileContent["users"][x+1]["trust"] == 0:
                print("- "+json_fileContent["users"][x+1]["userid"])
            elif json_fileContent["users"][x+1]["trust"] == 1:
                list_of_users.append([json_fileContent["users"][x+1]["userid"], x+1])

        print("\n\nYou have " + str(len(list_of_users)) + " requests from:\n")
        for cursor in range(len(list_of_users)):
            print(str(cursor) + " - " + list_of_users[cursor][0])

        answer = raw_input("\n\nDo you want to accept a request? (yes/no)\n=> ")
        if answer == "y" or answer == "yes" or answer == "Yes" or answer == "Y":
            second_answer = raw_input("\nWho would you like to choose from the list? (select them by the number in front of them)\n=> ")
            send_reply_to_request(list_of_users[int(second_answer)])
    except:
        print(spacer + "Somehow the request process has had an error")

def send_request(): # Create request to send to contacts
    
    questions = ["What is the address of the contact you are trying to reach?", "Who do you want to request a friendship from?", "Who, address?"]
    contact = raw_input(spacer + questions[random.randint(0, len(questions)-1)] + " eg. abcd#1234567890@x.x.x.x\n=> ")

    if ("#" in contact and "@" in contact):
        contact_id = ''
        contact_ip = ''
        ip_side = False
        for cursor in range(len(contact)):
            if ip_side == False and contact[cursor] != "@":
                contact_id = contact_id + contact[cursor]
            elif ip_side == False and contact[cursor] == "@":
                ip_side = True
            elif ip_side:
                contact_ip = contact_ip + contact[cursor]
                

        userblock = {}
        userblock["userid"] = contact_id
        userblock["address"] = contact_ip
        userblock["trust"] = 0
        json_fileContent["users"].append(userblock)
        cursor = len(json_fileContent["users"]) - 1

        if (contact_id == json_fileContent["users"][cursor]['userid']):
            communications["request"].append(cursor)
    
    
        print(spacer + "Request added to the list, once " + contact_id + " is connected the request will be sent at " + contact_ip)
    else:
        print(spacer + "There was an error with the input you gave, remember the users are represented like > abcd#1234567890@x.x.x.x")
    

    

def send_reply_to_request(data): # Send replies to the requests

    contact_id = data[0]
    contact_ip = json_fileContent["users"][data[1]]["address"]

    json_fileContent["users"][data[1]]["trust"] = 2
    json_fileContent["users"][data[1]]["trusted"] =  []
    communications["cttUpdate"] = True

    # Creating chat block for the user
    newUserChatBlock = {}
    newUserChatBlock["userid"] = contact_id
    newUserChatBlock["hashesFrom"] = []
    newUserChatBlock["hashesFrom"].append(base64.b64encode(rsa.compute_hash(json_fileContent["users"][0]["userid"].encode('utf8'), 'SHA-1')).decode('utf8'))
    newUserChatBlock["logFrom"] = []
    newUserChatBlock["hashesTo"] = []
    newUserChatBlock["hashesTo"].append(base64.b64encode(rsa.compute_hash(data[0].encode('utf8'), 'SHA-1')).decode('utf8'))
    newUserChatBlock["logTo"] = []
    json_chatLogContent["chats"].append(newUserChatBlock)

    communications["request"].append(data[1])
    print(spacer + data[0] + " has been added.\nReply has been sent.")
    raw_input("\nEnter to continue")
    return


def get_auth_profile(): # Create a profile json document to share
    profile = {}
    profile['user'] = json_fileContent["users"][0]["user"]
    profile['userid'] = json_fileContent["users"][0]["userid"]
    profile['signature'] = json_fileContent["users"][0]["signature"]
    profile['publickey'] = {}
    profile['publickey']['n'] = json_fileContent["users"][0]["publickey"]["n"]
    profile['publickey']['e'] = json_fileContent["users"][0]["publickey"]["e"]
    return split_msgs(json.dumps(profile)), rsa.compute_hash(json.dumps(profile).encode('utf8'), 'SHA-1')

def split_msgs(text): # Method to split message to 500 character long blocks on an array
    counter = 0
    newtext = ''
    for cursor in range(len(text)):
        if counter == 500:
            newtext = newtext + "^%#separator#%^"
            counter = 0
        newtext = newtext + text[cursor]
        counter = counter + 1
    array_of_messages = newtext.split("^%#separator#%^")

    
    return array_of_messages

def send_msg(): # Method to create messages and send them to the communicator
    try:
        got_a_name = False
        host_receiver = ''
        questions = ["Who are you trying to reach?", "Who do you want to send a message to?", "Who?"]
        while got_a_name == False:
            print(spacer + questions[random.randint(0, len(questions)-1)])
            index = 0
            for x in range(len(json_fileContent["users"])-1):
                if json_fileContent["users"][x+1]["trust"] > 1:
                    print("\n("+str(x+1)+") " + json_fileContent["users"][x+1]["userid"])

            answer = int(raw_input("\n=> "))
            # verify
            r_sure = raw_input("\nDo you want to send the message to " + json_fileContent["users"][answer]["userid"] + "? (yes/no) \n=> ")
            if r_sure == "yes" or r_sure == "Yes" or r_sure == "y" or r_sure == "Y":
                message = raw_input(spacer + "Write the message\n=> ")
                r_sure_again = raw_input("This is your message:\n'" + message + "'\nDo you want to send this message? (yes/no) \n=> ")
                if r_sure_again == "yes" or r_sure_again == "Yes" or r_sure_again == "y" or r_sure_again == "Y":
                    #Do the encryption and all
                    json_message = {}
                    json_message["userid"] = json_fileContent["users"][0]["userid"]
                    json_message["msg"] = message
                    json_message["time"] = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

                    ## Generating new hash for the message
                    chatBlockCursor = 0
                    for each in json_chatLogContent['chats']:
                        if each['userid'] != json_fileContent["users"][answer]["userid"]:
                            chatBlockCursor = chatBlockCursor + 1
                        else:
                            break

                    
                    # Verify and create next hash
                    message_chain_hash = rsa.compute_hash((
                                json_chatLogContent['chats'][chatBlockCursor]['hashesTo']
                                [len(json_chatLogContent['chats'][chatBlockCursor]['hashesTo'])-1]
                                +json.dumps(json_message)).encode('utf8'), 'SHA-1')
                    ## receiving that from another delivery so like self.receiver_mode = extra   code = 'hsh'
                    

                    array_of_messages_auth = get_auth_profile()


                    #rsa only encrypts 501 bytes
                    array_of_messages_message = split_msgs(str(json_message))

                    crypted_messages = []
                    for each in array_of_messages_message:
                        crypted_messages.append(base64.b64encode(rsa.encrypt(each.encode('utf8'), rsa.PublicKey(json_fileContent["users"][answer]["publickey"]["n"], json_fileContent["users"][answer]["publickey"]["e"]))).decode('utf8'))

                    signature = rsa.sign_hash(rsa.compute_hash(str(json_message).encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1')

                    currentChatBlock = {}
                    currentChatBlock['contactno'] = answer
                    currentChatBlock['chat'] = crypted_messages
                    currentChatBlock['messagehash'] = base64.b64encode(str(json_message).encode('utf8')).decode('utf8')
                    currentChatBlock['hash'] = base64.b64encode(message_chain_hash).decode('utf8')

                    logm(json_chatLogContent['chats'][chatBlockCursor]['hashesTo']
                                [len(json_chatLogContent['chats'][chatBlockCursor]['hashesTo'])-1] + "\nMessage chain hash " + currentChatBlock['hash'])
                    
                    currentChatBlock['signature'] = base64.b64encode(signature).decode('utf8')

                    json_chatLogContent['chats'][chatBlockCursor]['hashesTo'].append(base64.b64encode(message_chain_hash).decode('utf8')) # Added to chat logs

                    json_chatLogContent['chats'][chatBlockCursor]['logTo'].append(json_message)
                    

                    communications['chats'].append(currentChatBlock)
                    
                    got_a_name = True
                    print(spacer + "Your message is ready to be sent")

                    
                    
    except Exception as e:
        logm("send_msg()")
        logm(e)
        print(spacer + "Failed to send message")
    return






################################################################# Tha communicator



def auth_starter(ip, array, socketToSend): # Client autherticator for new users
    socketToSend.connect((ip, serverPort))
    
    test = ''
    for x in array:
        test = test + x
    logm("Connected to " + ip)
    socketToSend.send(("who" + str(len(array))).encode('utf8'))#+str(len(profile.encode('utf8')))
    time.sleep(1)
    for x in array:
        socketToSend.send(x.encode('utf8'))
        time.sleep(1)

    logm("Request sent to " + ip)
    return socketToSend, socketToSend.recv(4096)

def auth_trust(user, socketToSend): # Client autherticator for trusted users
    verified = False
    try:
        socketToSend.send(rsa.encrypt(json_fileContent['users'][0]['userid'].encode('utf8'), rsa.PublicKey(user['publickey']['n'], user['publickey']['e'])))
        time.sleep(1)
        socketToSend.send(rsa.sign_hash(rsa.compute_hash(json_fileContent['users'][0]['userid'].encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1'))
        logm("Sending auth")
        contactId = socketToSend.recv(4096)
        signature = socketToSend.recv(4096)
        logm("Receiving auth")
        contactId = rsa.decrypt(contactId, user_private_key).decode('utf8')
        if (contactId == user['userid']):
            logm("Right auth")
            if (rsa.verify(contactId.encode('utf8'), signature, rsa.PublicKey(user['publickey']['n'], user['publickey']['e']))):
                logm("Verified auth")
                verified = True
        return verified, socketToSend
    except Exception as e:
        logm("auth_trust(user, socketToSend)")
        logm(e)
    return verified, socketToSend

def auth_trusted(user, socketToSend): # Client autherticator for contact's trusted users
    verified = False
    try:
        socketToSend.send(rsa.encrypt(json_fileContent['users'][0]['userid'].encode('utf8'), rsa.PublicKey(user['publickey']['n'], user['publickey']['e'])))
        time.sleep(1)
        socketToSend.send(rsa.sign_hash(rsa.compute_hash(json_fileContent['users'][0]['userid'].encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1'))
        contactId = socketToSend.recv(4096)
        signature = socketToSend.recv(4096)
        contactId = rsa.decrypt(contactId, user_private_key).decode('utf8')
        if (contactId == user['userid']):
            if (rsa.verify(contactId.encode('utf8'), signature, rsa.PublicKey(user['publickey']['n'], user['publickey']['e']))):
                verified = True
    except Exception as e:
        logm("auth_trusted(user, socketToSend)")
        logm(e)

    return verified, socketToSend

def who_is(userid): # Method to find contact index on the list of contacts
    contactNo = 0
    for each_user in range(len(json_fileContent['users'])-1):
        if json_fileContent['users'][each_user+1]['userid'] == userid:
            contactNo = each_user+1
            break

    return contactNo

def encrypt_sign(text, pubkey): # Method to split messages, encrypt them and return it with a signature
    sign = rsa.sign_hash(rsa.compute_hash(text.encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1')
    array = split_msgs(text)
    crypted_array = []
    for each in array:
        crypted_array.append(rsa.encrypt(each.encode('utf8'), rsa.PublicKey(pubkey['n'], pubkey['e'])))
    return crypted_array, sign

def find_pchat_hash(jsonValue): # Find "pchat" index on list of sent pchats
    the_hash = rsa.compute_hash(str(jsonValue).encode('utf8'), 'SHA-1')
    for each in range(len(communications['sentToPChats'])):
        if base64.b64decode(communications['sentToPChats'][each]['pchatHash'].encode('utf8')) == the_hash:
            return each

def logm(text): # Method to log
    log.append(text)
    

def save_all_data(): # Method to save data using fernet encryption

    f = Fernet(fernetKey)
    fileContent = f.encrypt(json.dumps(json_fileContent).encode('utf8'))
    
    file = open('userblocks', 'wb')
    file.write(fileContent)
    file.close()

    chatLogContent = f.encrypt(json.dumps(json_chatLogContent).encode('utf8'))
    
    file = open('chatblocks', 'wb')
    file.write(chatLogContent)
    file.close()
    
    commsFileContent = f.encrypt(json.dumps(communications).encode('utf8'))
    
    file = open('comms', 'wb')
    file.write(commsFileContent)
    file.close()


def communicator(): # Main communications method, handles saving data, and sending all the requests "who" "ctt" "pos" "pch"
    
    (array_of_profile, profile_hash) = get_auth_profile()
    global run_the_server
    # Communicate with everyone
    # ==================================================== Check requests to send
    while run_the_server:
        #logm("Communications cycle")
        time.sleep(1)
        save_all_data()
        for each in communications["request"]: # For request is a 'who', profile, and receive hash
            logm("Sending request at " + str(json_fileContent['users'][each]['address']))
            try:
                socketToSend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                (socketToSend, received_profile_hash) = auth_starter(
                    json_fileContent['users'][each]['address'],
                    array_of_profile,
                    socketToSend)
                
                if (profile_hash == received_profile_hash):
                    communications["request"].remove(each)
                    logm(str(json_fileContent['users'][each]['address']) + " received request")
            except:
                logm("Failed to send request")

                
                
        # ==================================================== Send Tables
        # Create tables ================================

        if communications["cttUpdate"]:
            communications['cttWhoUpdated'] = []
            communications["cttUpdate"] = False
        current_ctt = {}
        current_ctt['ctt'] = [] # trusted list
        list_to_send_to = [] # trusted list
        for x in range(len(json_fileContent['users'])-1):
            if json_fileContent['users'][x+1]['trust'] >= 2:
                trusted_block = {}
                trusted_block['userid'] = json_fileContent['users'][x+1]['userid']
                trusted_block['address'] = json_fileContent['users'][x+1]['address']
                trusted_block['publickey'] = json_fileContent['users'][x+1]['publickey']
                current_ctt['ctt'].append(trusted_block)
                list_to_send_to.append(x+1)

        current_ctt_b64 = base64.b64encode(json.dumps(current_ctt['ctt']).encode('utf8')).decode('utf8')
        current_signature = rsa.sign_hash(rsa.compute_hash(current_ctt_b64.encode('utf8'), 'SHA-1'), user_private_key, 'SHA-1')

        array_of_current_ctt = split_msgs(current_ctt_b64)
        # Each to send tables ================================

        for each_user in list_to_send_to:
            try:
                if json_fileContent["users"][each_user]['userid'] not in communications['cttWhoUpdated']:
                    logm("Ctt to " + json_fileContent["users"][each_user]['userid'])
                    crypted_array_of_current_ctt = []
                    for each_msg_block in array_of_current_ctt:
                        crypted_array_of_current_ctt.append(rsa.encrypt(each_msg_block.encode('utf8'), rsa.PublicKey(json_fileContent["users"][each_user]["publickey"]["n"], json_fileContent["users"][each_user]["publickey"]["e"])))
                    
                    socketToSend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socketToSend.connect((json_fileContent["users"][each_user]["address"], serverPort))
                    time.sleep(1)
                    socketToSend.send(("ctt" + str(len(array_of_current_ctt))).encode('utf8'))#+str(len(profile.encode('utf8')))
                    
                    (verified, socketToSend) = auth_trust(json_fileContent["users"][each_user], socketToSend)
                    
                    # Authenticate
                    if (verified):
                        # Send Message
                        #logm("===========================================================================")
                        for x in crypted_array_of_current_ctt:
                            socketToSend.send(x)
                            time.sleep(0.5)
                            
                        socketToSend.send(current_signature)
         
                        received_message_signature = socketToSend.recv(4096)

                        if (rsa.verify(current_ctt_b64.encode('utf8'), received_message_signature, rsa.PublicKey(json_fileContent["users"][each_user]["publickey"]["n"], json_fileContent["users"][each_user]["publickey"]["e"]))):
                            communications['cttWhoUpdated'].append(json_fileContent["users"][each_user]['userid'])

            except Exception as e:
                logm("Ctt exchange")
                logm(e)

        
        # ==================================================== Check chats to send

        for each in communications['chats']:

            logm("Sent to pchat")
            # Send to pchats
            # 'pchat's are private/post chats, these are block that are send from 
            
            
            pchat_block = {}
            pchat_block['type'] = 0
            pchat_block['from'] = json_fileContent['users'][0]['userid']
            pchat_block['to'] = json_fileContent['users'][each['contactno']]['userid']
            pchat_block['chat'] = {}
            pchat_block['chat']['chat'] = each['chat']
            pchat_block['chat']['hash'] = each['hash']
            pchat_block['chat']['signature'] = each['signature']

            pchat_sent_to = {}
            pchat_sent_to['pchatHash'] = base64.b64encode(rsa.compute_hash(str(pchat_block).encode('utf8'), 'SHA-1')).decode('utf8')
            pchat_sent_to['sent_to'] = []
            communications['sentToPChats'].append(pchat_sent_to)
            communications['pchats'].append(pchat_block)
            communications['chats'].remove(each)
            


        # ==================================================== Check chats to send
        

        for each in communications['pchats']:
            try:
                #'pos'
                contactNo = who_is(each['to'])
                logm("Sending pChats 'pos' to " + json_fileContent['users'][contactNo]['userid'])
                
                crypted_pchat_array, pchat_sign = encrypt_sign(json.dumps(each), json_fileContent['users'][contactNo]['publickey'])
                

                socketToSend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socketToSend.connect((json_fileContent['users'][contactNo]['address'], serverPort))
                socketToSend.send(("pos" + str(len(crypted_pchat_array))).encode('utf8'))#+str(len(profile.encode('utf8')))
                time.sleep(1)
                (verified, socketToSend) = auth_trust(json_fileContent['users'][contactNo], socketToSend)
                if verified:
                    for each_pchat in crypted_pchat_array:
                        socketToSend.send(each_pchat)
                        time.sleep(1)
                    
                    socketToSend.send(pchat_sign)
                    received_message_signature = socketToSend.recv(4096)

                    if (rsa.verify(json.dumps(each).encode('utf8'), received_message_signature, rsa.PublicKey(json_fileContent['users'][contactNo]['publickey']['n'], json_fileContent['users'][contactNo]['publickey']['e']))):
                        communications['pchats'].remove(each)
            except Exception as e:
                logm("pChats 'pos'")
                logm(e)
                if (each['from'] == json_fileContent['users'][0]['userid']):
                    contactNo = who_is(each['to'])
                    logm("One of your pChats found to send to trusted")
                    for each_trusted_person in json_fileContent['users'][contactNo]['trusted']:
                        pchat_com_cursor = find_pchat_hash(each)
                        if each_trusted_person['userid'] != json_fileContent['users'][0]['userid']:
                            logm("'connecting to " + each_trusted_person['userid'])
                            if each_trusted_person['userid'] not in communications['sentToPChats'][pchat_com_cursor]['sent_to']:
                                socketToSend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                try:
                                    crypted_pchat_array, pchat_sign = encrypt_sign(json.dumps(each), each_trusted_person['publickey'])
                                    socketToSend.connect((each_trusted_person['address'], serverPort))
                                    socketToSend.send(("pch" + str(len(crypted_pchat_array))).encode('utf8'))
                                    time.sleep(1)
                                    logm("'pch' sent" + each_trusted_person['userid'])
                                    (verified, socketToSend) = auth_trust(each_trusted_person, socketToSend)
                                    if verified:
                                        logm("Trusted user verified!")
                                        for each_pchat in crypted_pchat_array:
                                            socketToSend.send(each_pchat)
                                            time.sleep(1)
                            
                                        socketToSend.send(pchat_sign)
                                        received_message_signature = socketToSend.recv(4096)

                                        if (rsa.verify(json.dumps(each).encode('utf8'), received_message_signature, rsa.PublicKey(each_trusted_person['publickey']['n'], each_trusted_person['publickey']['e']))):
                                            communications['sentToPChats'][pchat_com_cursor]['sent_to'].append(each_trusted_person['userid'])
                                            logm("pChat sent to " + each_trusted_person['userid'])
                                            if len(communications['sentToPChats'][pchat_com_cursor]['sent_to']) == len(json_fileContent['users'][contactNo]['trusted'])-1:
                                                communications['pchats'].remove(each)

                                except Exception as e:
                                    logm("PChats 'pch'")
                                    logm(e)
                else:
                    # try to eliminate if its been more than a day or two\
                    if (int(each['time']) < int(datetime.datetime.now().strftime("%Y%m%d%H%M%S"))):
                        communications['pchats'].remove(each)


# ================================== Send missing data report

        for each in communications['missing']:
            
            pchat_block = {}
            pchat_block['type'] = 1
            pchat_block['from'] = json_fileContent['users'][0]['userid']
            pchat_block['to'] = each['userid']

            contactNo = who_is(each['userid'])

            missing_hash_report = {}
            missing_hash_report["last_hash"] = each["last_hash"]

            crypted_pchat_array, pchat_sign = encrypt_sign(json.dumps(missing_hash_report), ['publickey'])
            
            pchat_block['chat'] = {}
            pchat_block['chat']['msg'] = crypted_pchat_array
            pchat_block['chat']['hash'] = rsa.compute_rsa(json.dumps(missing_hash_report).encode('utf8'), 'SHA-1')
            pchat_block['chat']['signature'] = pchat_sign
            
            pchat_sent_to = {}
            pchat_sent_to['pchatHash'] = base64.b64encode(rsa.compute_hash(str(pchat_block).encode('utf8'), 'SHA-1')).decode('utf8')
            pchat_sent_to['sent_to'] = []
            
            communications['sentToPChats'].append(pchat_sent_to)
            communications['pchats'].append(pchat_block)
            communications['missing'].remove(each)
            
                
    
    


################################################################# The running


the_background_server = threading.Thread(target=run_the_server)
the_background_communicator = threading.Thread(target=communicator)
# Adding threads for data

run_in_the_background()
run_the_main()






