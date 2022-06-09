#!/usr/bin/env python3
"""Validate yubikey OTPs sent to port 8975 on this system, and if valid, run a command that makes a change on the system."""
#Dedicated to Matthew Hathaway, who left us too soon.

__version__ = '1.5.3'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2011-2022, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Development'				#Prototype, Development or Production


import sys
import socket
import re
import subprocess
import os
import syslog
import random						#Pick a random API server

try:
	import secrets					#To generate a nonce.  Note: this was added in Python 3.6 (check with "python3 -V").
	secrets_loaded = True
except ImportError:
	secrets_loaded = False				#We'll fallback to using random.choice for python 3.5 and below

#try:
if sys.version_info[0] >= 3:
	import urllib.request as urllib2		#For python 3
#except ImportError:
else:
	import urllib2					#Fallback if run under python2


##  --------------------------------------------------------
##  constants
##  --------------------------------------------------------
#URLs for api.yubico.com and api2.yubico.com through api5.yubico.com.
YubicoAuthSrvURLprefixes = ['https://api.yubico.com/wsapi/2.0/verify?id=', 'https://api2.yubico.com/wsapi/2.0/verify?id=', 'https://api3.yubico.com/wsapi/2.0/verify?id=', 'https://api4.yubico.com/wsapi/2.0/verify?id=', 'https://api5.yubico.com/wsapi/2.0/verify?id=']
AuthSrvRespRegex = re.compile('^status=(?P<rc>\w{2})')
#Note; will not succeed on dvorak.
#Note; yubico OTP can be from 34 to 48 characters (2-16 character ID followed by an (always 32 character) OTP.  To retrieve ID, remove final 32 characters.
KeyRegex = re.compile('[bcdefghijklnrtuv]{44}')
hex_chars = '0123456789abcdef'


#======== Functions ========
def Debug(should_debug: bool, DebugStr: str):
	"""Prints a note to stderr and saves to syslog."""

	if should_debug:
		sys.stderr.write(DebugStr + '\n')
		sys.stderr.flush()
		syslog.syslog(DebugStr)


def ReceiveKey(net_socket) -> str:
	"""Look for a potential yubikey 44 character code in the block of data from the client.  If received, send it up."""
	#Unclear how to add a ": type" entry for a socket/bytes.

	InText = ''
	Result = ''
	#Check to see if we've already accumulated 16K of input; if so, stop accepting data and close connection.
	while KeyRegex.search(InText) is None and len(InText) < 16385:
		InData = net_socket.recv(4096).decode("utf-8", 'replace')
		if not InData:
			#OK, instead of exiting, just return an empty string so we can go back to listen for more connections.
			return ""
			#raise EOFError('Socket closed before we received the entire key')
		InText += InData
	Match = KeyRegex.search(InText)
	if Match:
		Result = InText[Match.start():Match.end()]
	return Result


def VerifyOTP(clientId: str, otp: str) -> bool:
	"""Contact Yubico's authentication server to validate key.  Return true if valid, false otherwise."""
	#Reference: https://developers.yubico.com/yubikey-val/Getting_Started_Writing_Clients.html

	if secrets_loaded:
		nonce = secrets.token_hex(20)
	else:
		nonce = ''.join([random.choice(hex_chars) for index in range(40)])

	#We select a random server out of the list of 5 available for each new check.
	YubicoAuthSrvURL = random.choice(YubicoAuthSrvURLprefixes) + clientId + "&otp=" + otp + '&nonce=' + nonce
	#Debug(cl_args['devel'], 'Connecting to: ' + YubicoAuthSrvURL)
	fh = urllib2.urlopen(YubicoAuthSrvURL)   # URL response assigned to a file handle/object

	#Future; check hash

	nonce_matches = False
	otp_matches = False
	auth_success = False
	for line in fh:
		line_string = line.decode("utf-8", 'replace').strip('\r\n')		#Note that lines end in \r\n

		#confirm that we get back the same otp
		if line_string == 'otp=' + otp:
			otp_matches = True

		#confirm that we get back the same nonce
		if line_string == 'nonce=' + nonce:
			nonce_matches = True

		#Confirm that status is "OK"
		#if line_string == 'status=OK':
		AuthSrvRespMatch = AuthSrvRespRegex.search(line_string)
		if AuthSrvRespMatch and AuthSrvRespMatch.group('rc') == 'OK':
			auth_success = True

	return otp_matches and nonce_matches and auth_success




#======== Program Options and defaults ========
DefaultListenPort=8975
DefaultAuthCommand="/usr/bin/yubiknock-authorize"



if __name__ == '__main__':
	syslog.openlog('Yubiknock ')

	import argparse

	#======== Process command line options ========
	parser = argparse.ArgumentParser(description='yubiknock version ' + str(__version__))
	parser.add_argument('-e', '--externalprog', help='External program to handle system change', required=False, default=DefaultAuthCommand)	#Later change to default='' if we handle firewall changes internally
	parser.add_argument('-c', '--clientid', help='Client ID assigned by Yubico', type=str, required=True)
	parser.add_argument('-p', '--port', help='Listening port', type=int, required=False, default=DefaultListenPort)
	parser.add_argument('-d', '--devel', help='Enable development/debug statements', required=False, default=False, action='store_true')
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	#Check external program, if specified
	if cl_args['externalprog'] and (not os.path.isfile(cl_args['externalprog']) or not os.access(cl_args['externalprog'], os.X_OK)):
		Debug(cl_args['devel'], str(cl_args['externalprog']) + " does not appear to be an executable program, exiting.")
		sys.exit(1)


	#======== Set up server ========
	try:
		ListenSocket = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)		#We try to open an IPv6 listener (which also accepts IPv4).  If this fails (Gentoo allows a system with no ipv6)...
	except OSError:
		ListenSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)		#...we retry with IPv4 only.

	try:
		ListenSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		ListenSocket.bind(("", int(cl_args['port'])))
		ListenSocket.listen(1)		#Increase for larger queue of backlogged connection requests
	except PermissionError:
		Debug(cl_args['devel'], "Unable to Listen to port " + str(cl_args['port']) + ", exiting.")
		sys.exit(1)

	#Continuous loop, accept a connection and process input.
	while True:
		#Debug(cl_args['devel'], 'Listening at' + ListenSocket.getsockname())
		try:
			sc, sockname = ListenSocket.accept()
		except KeyboardInterrupt:
			Debug(True, 'Exiting on Ctrl-C.')
			sys.exit(0)
		remote_ip = sc.getpeername()[0]
		if remote_ip.startswith('::ffff:'):
			remote_ip = remote_ip.replace('::ffff:', '')				#When listening on :: and an IPv4 connection is received, the remote_ip looks like '::ffff:8.8.8.8'.  This "replace" puts it back in standard IPv4 format.

		#Debug(cl_args['devel'], 'Remote IP is' + remote_ip)
		InKey = ReceiveKey(sc)


		if InKey == '':
			#Feedback to the tcp client is deliberately minimal until we have a valid OTP.
			sc.sendall(b'HTTP/1.0 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nNo input.\n')
		else:
			Debug(cl_args['devel'], 'Received yubikey ' + InKey + ' from ' + remote_ip)
			#For debugging.
			#sc.sendall(b'Yubikey received.\n')

			if VerifyOTP(cl_args['clientid'], InKey):
				sc.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n')
				Debug(cl_args['devel'], 'Received yubikey ' + InKey + ' from ' + remote_ip + ', key verified.')
				sc.sendall(b'Yubikey verified.\n')
				try:
					RetCode = subprocess.call([cl_args['externalprog'], remote_ip, InKey[0:12]])
					Debug(cl_args['devel'], 'Received yubikey ' + InKey + ' from ' + remote_ip + ', auth program returned ' + str(RetCode))
					sc.sendall(b'Return code is ' + str(RetCode).encode('utf-8', errors='ignore') + b'\n')
				except:
					Debug(cl_args['devel'], 'Unable to execute ' + cl_args['externalprog'])
					sc.sendall(b'Unable to continue, please see server logs.')
			else:
				sc.sendall(b'HTTP/1.0 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nNot accepted.\n')
				Debug(cl_args['devel'], 'Not able to validate yubikey ' + InKey + ' from ' + remote_ip)

		sc.close()
		#Debug(cl_args['devel'], 'Socket closed')
