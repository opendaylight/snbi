#!/usr/bin/env python3

"""
Anil R (anr2@cisco.com)

This wrapper allows you to connect to the snbi daemon using telnet.
Executing the wrapper: ./console_wrapper -d <daemon or program> -p <port_number>
port_number is the listening port number. If port number is not specified
by default port 1250 will be used.
daemon or program with complete or relative path must be provided. If this is not
provided by default ../bin/snbi.d will be used.
For help execute ./console_wrapper --h
"""

import socket
import os
import sys
import subprocess
import select
from _socket import AF_INET, SOCK_STREAM
import threading
import re
import telnetlib
import struct
import binascii
from optparse import OptionParser

#Parse command line arguments
#Listening port passed as argument. Default port number is 1250
usage = "usage: %prog [-p|--port <port number>]"
parser = OptionParser(usage=usage)
parser.add_option("-p","--port", dest="listen_port", default = 1250,help="listening port number, default is %default")
parser.add_option("-d","--daemon", dest="daemon", default = "../bin/snbi.d", help="Daemon or program to execute, default is %default")
(options,args) = parser.parse_args()

#Set host & port number
host = "0.0.0.0"
if options.listen_port:
    port = int(options.listen_port) 

if options.daemon:
    program = options.daemon         

print("Daemon: ", program)
print("listening on port", port)
telnet_options = (255, 251, 3)
ns = struct.Struct('B B B')
telnet_opt = ns.pack(*telnet_options)

s = socket.socket(AF_INET,SOCK_STREAM,0)
s.bind((host, port))
s.listen(0)

class ReaderThread(threading.Thread):

    def __init__(self, stream,cid):
        threading.Thread.__init__(self)
        self.stream = stream
        self.cid = cid

    def run(self):
        while True:
            line = self.stream.readline()
            if len(line) == 0:
                break
            #print('before: ',line)
            if re.match('snbi.d \(*.*\)* *>.*\n',line.decode('utf-8')):
                #print('In snbi.d handling')
                line =  line.decode('utf-8').rstrip('\n')
                line = line.rstrip('\r')
                line = line.encode('utf-8')
            line = '\n' + line.decode('utf-8')
            line = line.encode('utf-8')
            self.cid.sendall(line)
            #print('after: ',line)
   
parent, child = socket.socketpair()
pid = os.fork()
if pid == 0:
    #Child
    parent.close()
    prog = 'stdbuf -oL ' + program + ' -i'
    proc = subprocess.Popen(prog,
                        bufsize=0,
                        shell=True,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        close_fds=True
                        )
    reader = ReaderThread(proc.stdout,child)
    reader.start()
    inp = [child]
    stop_loop = 0
    while True:
        iready,oready,eready = select.select(inp,[],[])
        for val in iready:
            if val == child:
                message = child.recv(1024)
                try:
                    proc.stdin.write(message) 
                except (BrokenPipeError, IOError):
                    stop_loop = 1
                    break
        if stop_loop :
            break
    # Wait until subprocess is done
    proc.wait()
    # Wait until we've processed all output
    reader.join()                           
else :
    #Parent
    child.close()
    input = [parent,s]
    p = 0 
    while True:        
        inputready,outputready,exceptready = select.select(input,[],[])
        for val in inputready:
            if val == parent:
                #print('In parent')
                op = parent.recv(1024)            
                #print('Sending : ', op)
                if op:
                    p.send(op)
                else:
                    print('Closed application')
                    if p:
                        print('Closing connection')
                        p.shutdown(socket.SHUT_RDWR)
                        p.close()
                    s.shutdown(socket.SHUT_RDWR)
                    s.close()
                    exit()                                                
            elif val == s:
                #print('In connection accept')
                c, addr = s.accept() 
                input.append(c)
                p = c
                input.remove(s)
                p.send(telnet_opt)
                data = c.recv(80)
            elif val == p:
                #print('In data receive')
                data = val.recv(80)            
                #print(data) 
                if data:
                    if data == b'\r\x00':
                        #print("In CR handling")
                        parent.sendall('\r\n'.encode('utf-8'))
                        parent.sendall('\r\n'.encode('utf-8'))
                    elif data == b'?':
                        parent.sendall(data)
                        parent.sendall('\r\n'.encode('utf-8'))
                    else:
                        parent.sendall(data) 
                else:
                    #print('null data')
                    input.append(s)
                    input.remove(p)
                    p.close()
