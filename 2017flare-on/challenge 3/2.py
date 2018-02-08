import socket
import os
import time
import threading

def run():
    os.system('C:\\Users\\yinqin\\Desktop\\greek_to_me.exe')

for i in range(255):
    
    new = threading.Thread(target=run)
    new.start()
    
    time.sleep(0.3)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 2222))

    s.send('%s234'%chr(i))

    data = s.recv(1024)

    print data

    if data == 'Nope, that\'s not it.':
        print i
    else:
        print i
        raw_input()
    
    s.close()