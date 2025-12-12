#!/usr/bin/env python3
"""
oncetimepad: predictable one-time pad encryption

:Copyright:
    Copyright 2018 Giovanni Vigna.  All Rights Reserved.
"""

import sys
import os
import random
import time
import signal
import base64
import datetime
import optparse
import logging

# 1538763124
DURATION = 10

s_nouns = ["A dude", "My ant", "The king", "Some guy", "A cat with rabies", "A sloth", "Your homie", "This cool guy my gardener met yesterday", "Superman"]
p_nouns = ["These dudes", "Both of my parents", "All the kings of the world", "Some guys", "All of a cattery's cats", "The multitude of sloths living under your bed", "Your homies", "Like, these, like, all these people", "Supermen"]
s_verbs = ["eats", "kicks", "gives", "treats", "meets with", "creates", "hacks", "configures", "spies on", "meows on", "flees from", "tries to automate", "explodes"]
p_verbs = ["eat", "kick", "give", "treat", "meet with", "create", "hack", "configure", "spy on", "retard", "meow on", "flee from", "try to automate", "explode"]
infinitives = ["to make a pie.", "for no apparent reason.", "because the sky is green.", "for a disease.", "to be able to make toast explode.", "to know more about archeology."]

def sentence_maker():
	return "%s %s %s %s" % (
		random.choice(s_nouns), 
		random.choice(s_verbs), 
		random.choice(p_nouns).lower(), 
		random.choice(infinitives))

def decrypt(seed, message, logger):
	seed = int(seed)
	logger.debug("Seed: %d (%s)" % (seed, type(seed))) 
	
	encrypted_data = base64.b64decode(message)
	logger.debug("Encrypted data: %s" % encrypted_data)

	encrypted_bytes = bytearray(encrypted_data)
	encryption_bytes = bytearray(encrypted_data)
	decrypted_bytes = bytearray(encrypted_data)
	
	random.seed(seed)
	for i in range(len(encrypted_bytes)):
		encryption_bytes[i] = random.randint(0, 255)
		decrypted_bytes[i] = encrypted_bytes[i] ^ encryption_bytes[i]
	
	data = "".join(chr(val) for val in decrypted_bytes)
	logger.debug("Encryption pad: %s" % repr(encryption_bytes))

	print(data)
	return 0

def handler(signum, frame):
    print("Timeout!")
    sys.exit(1)

def main(argv):
	parser = optparse.OptionParser(usage="""
================================================================================
""" + __doc__.strip() + """
================================================================================

Usage: oncetimepad generates a one-time-pad encrypted message
""")	
	parser.add_option("-d", "--debug",
                      dest="debug", action="store_true",
                      help="enables debugging",
                      default=False)
	parser.add_option("-e", "--encoding",
                      dest="encoding",
                      help="defines string encoding",
                      default='ascii')
	parser.add_option("-m", "--message",
                      dest="message", type="string",
					  help="base64 encoded message")
	parser.add_option("-s", "--seed",
                      dest="seed", type="string",
                      help="seed")

	(cmdline_options, args) = parser.parse_args()
	if len(args) != 0:
		parser.print_help()
		return 1

	if cmdline_options.debug == True:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=logging.INFO)

	encoding = cmdline_options.encoding

	logger = logging.getLogger('oncetimepad')
	logger.debug("Starting...")
	
	if cmdline_options.seed:	
		if not cmdline_options.message:
			logger.error("You need to specify a message")
			return 1
		decrypt(cmdline_options.seed, cmdline_options.message, logger)
		return 0

	signal.alarm(DURATION)
	signal.signal(signal.SIGALRM, handler)
    
	seed = int(time.time())
	time_string = time.strftime("%a, %d %b %Y %H:%M", time.gmtime(seed))
	logger.debug(f"Seed: {seed}")
	
	print(f"""Oncetimepad service started at {time_string}...

The oncetimepad service provides communication protected with a freshly-seeded, \
unbreakable one-time-pad-based encryption algorithm based on Python's excellent random number generator.
In order to verify the possession of the correct one-time pad, please decrypt \
the following sentence (base64-encoded for your convenience).
	""")

	sentence = sentence_maker()
	logger.debug(f"Sentence: {sentence}")	

	decrypted_bytes = bytearray(sentence, encoding)
	encrypted_bytes = bytearray(sentence, encoding)
	encryption_bytes = bytearray(sentence, encoding)
	
	random.seed(seed)
	for i in range(len(encrypted_bytes)):
		encryption_bytes[i] = random.randint(0, 255)
		encrypted_bytes[i] = decrypted_bytes[i] ^ encryption_bytes[i]
	
	#encrypted_data = "".join(chr(val) for val in encrypted_bytes)
	logger.debug(f"Encrypted data: {repr(encrypted_bytes)}")
	logger.debug(f"Encryption pad: {repr(encryption_bytes)}")

	#b64_data = base64.b64encode(encrypted_data)
	b64_data = base64.b64encode(encrypted_bytes)
	#logger.debug(type(b64_data))
	data = "".join(chr(val) for val in b64_data)
	
	print("---- Start of Message ----")
	print(data)
	print("---- End of Message ----")
	
	answer = input("Sentence: ")

	if answer.strip().lower() == sentence.strip().lower():
		print(f"Correct! You obviously have stored the correct one-time pad key. The flag is:")
		print(open("/flag.txt", "r").read())
	else:
		print("Incorrect! You must be using the wrong pad, or you might be trying some nasty shenanigans!")

	return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
