#coding:utf-8
from threading import Thread
import struct
import time
import hashlib
import base64
import socket
import time
import types
import multiprocessing
import os

from sshConn import SSHConn
from webConn import WebConn

mode = "initialize"
pic_size = 0
pic_receive = 0
pic = ""
pic_repeat = []

# 配置远程服务器的IP，帐号，密码，端口等
ip1 = "172.16.201.71"
user1 = "root"
passwd1 = 'xtptbim@2018'
logname_doctool = 'cbim-doctool-backend-test'
logname_utmt = 'cbim-utmt-backend-test'

ip2 = "172.16.201.122"
user2 = "root"
passwd2 = '0!tQaQoiZs'
logname2 = 'cbim-doctool-backend-devonline'


class returnCrossDomain(Thread):

    def __init__(self, connection):
        Thread.__init__(self)
        self.con = connection
        self.isHandleShake = False
        self.ClientData = ''
        self.func=''

    def run(self):
        global mode
        global pic_size
        global pic_receive
        global pic
        global pic_repeat
        while True:
            if not self.isHandleShake:
                # 开始握手阶段
                header = self.analyzeReq()
                secKey = header['Sec-WebSocket-Key'];

                acceptKey = self.generateAcceptKey(secKey)

                response = "HTTP/1.1 101 Switching Protocols\r\n"
                response += "Upgrade: websocket\r\n"
                response += "Connection: Upgrade\r\n"
                response += "Sec-WebSocket-Accept: %s\r\n\r\n" % (acceptKey.decode('utf-8'))
                self.con.send(response.encode())
                self.isHandleShake = True
                if (mode == "initialize"):
                    mode = "get_order"
                print('response:\r\n' + response)
                # 握手阶段结束

                self.ClientData = self.readClientData()
                print('客户端数据：' + str(self.ClientData))

                # 读取页面数据
            elif mode == "get_order":
                if self.ClientData == 'doctool':
                    self.func='doctool'
                    self.log(ip1, user1, passwd1, logname_doctool,'doctool')
                elif self.ClientData == 'utmt':
                    self.func='utmt'
                    self.log(ip1, user1, passwd1, logname_utmt,'utmt')



    # 根据dockerId获取日志路径
    def logpath(self, ssh, logname):
        result = ssh.exec_command('docker ps')
        new = result.split('\n')
        containerId = '不知道'
        for i in new:
            print(i)
            if logname in i:
                containerId = i.split('   ')[0]
        print('容器id是： ' + containerId)
        result1 = ssh.exec_command('cd /var/lib/docker/containers/ ;ls')
        name = result1.split('\n')
        file = ''
        for i in name:
            if containerId in i:
                print(i)
                file = i
        # 远程服务器要被采集的日志路径
        logPath = 'tail -f /var/lib/docker/containers/' + file + '/' + file + '-json.log'
        return logPath

    def log(self, ip, user, passwd, logname,funcName):
        self.con.setblocking(0)  # 设置非阻塞  非常重要，这样就可以在没有前端消息时跳过recv，不必继续等着前端发送
        # 2、建立与产生日志服务器的连接
        ssh = SSHConn()
        ssh_t = ssh.get_ssh(ip, user, passwd)  # 连接远程服务器（日志所在的服务器）
        chan = ssh_t.get_transport().open_session()
        chan.setblocking(0)  # 设置非阻塞
        # 3、获取日志路径
        logPath = self.logpath(ssh, logname)
        # 4、获取日志
        chan.exec_command(logPath)
        flag=True
        while flag:
            while chan.recv_ready():
                self.ClientData = self.readClientData()
                if  self.ClientData is not None and  self.ClientData != self.func:
                    print('客户端数据：' + str( self.ClientData))
                    if  self.ClientData != funcName:
                        tip = '接下来展示' +  self.ClientData + '的日志'
                        self.send_msg(tip.encode('utf-8'))
                        flag = False
                        break
                log_msg = logname + bytes.decode(chan.recv(1000))  # 接收日志信息  不以字节显示，以utf-8显示
                print(log_msg)
                self.send_msg(log_msg.encode('utf-8'))
            self.ClientData = self.readClientData()
            if  self.ClientData is not None and  self.ClientData != self.func:
                print('客户端数据：' + str( self.ClientData))
                if  self.ClientData != funcName:
                    tip = '接下来展示' +  self.ClientData + '的日志'
                    self.send_msg(tip.encode('utf-8'))
                    flag = False
                    break

    def legal(self, string):  # python总会胡乱接收一些数据。。只好过滤掉
        if len(string) == 0:
            return 0
        elif len(string) <= 100:
            if self.loc(string) != len(string):
                return 0
            else:
                if mode != "get_pic":
                    return 1
                elif len(string) + pic_receive == pic_size:
                    return 1
                else:
                    return 0
        else:
            if self.loc(string) > 100:
                if mode != "get_pic":
                    return 1
                elif string[0:100] not in pic_repeat:
                    pic_repeat.append(string[0:100])
                    return 1
                else:
                    return -1  # 收到重复数据，需要重定位
            else:
                return 0

    def loc(self, string):
        i = 0
        while (i < len(string) and self.rightbase64(string[i])):
            i = i + 1
        return i

    def rightbase64(self, ch):
        if (ch >= "a") and (ch <= "z"):
            return 1
        elif (ch >= "A") and (ch <= "Z"):
            return 1
        elif (ch >= "0") and (ch <= "9"):
            return 1
        elif ch == '+' or ch == '/' or ch == '|' or ch == '=' or ch == ' ' or ch == "'" or ch == '!' or ch == ':':
            return 1
        else:
            return 0

    def analyzeReq(self):
        reqData = self.con.recv(1024).decode()
        reqList = reqData.split('\r\n')
        headers = {}
        for reqItem in reqList:
            if ': ' in reqItem:
                unit = reqItem.split(': ')
                headers[unit[0]] = unit[1]
        return headers

    def generateAcceptKey(self, secKey):
        sha1 = hashlib.sha1()
        sha1.update((secKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode())
        sha1_result = sha1.digest()
        acceptKey = base64.b64encode(sha1_result)
        return acceptKey

    def getDataLength(self):
        second8Bit = self.con.recv(1)
        second8Bit = struct.unpack('B', second8Bit)[0]
        masking = second8Bit >> 7
        dataLength = second8Bit & 0b01111111
        # print("dataLength:",dataLength)
        if dataLength <= 125:
            payDataLength = dataLength
        elif dataLength == 126:
            payDataLength = struct.unpack('H', self.con.recv(2))[0]
        elif dataLength == 127:
            payDataLength = struct.unpack('Q', self.con.recv(8))[0]
        self.masking = masking
        self.payDataLength = payDataLength
        # print("payDataLength:", payDataLength)

    #解析客户端传来的信息
    def readClientData(self):
        try:
            first8Bit = self.con.recv(1)
            if not len(first8Bit):
                return False
        except:                          #使用了非阻塞，那么这里的recv不会再等待客户端发送消息才继续执行，引来的问题是当没有客户端消息传来时执行recv方法会报错：无法立即完成一个非阻止性套接字操作.意思是：前端没有消息传来，所以我要报错了
            pass
        else:
            first8Bit = struct.unpack('B', first8Bit)[0]
            opcode = first8Bit & 0b00001111
            if opcode == 8:
                self.con.close()
            self.getDataLength()
            if self.masking == 1:
                maskingKey = self.con.recv(4)
            data = self.con.recv(self.payDataLength)

            if self.masking == 1:
                i = 0
                trueData = ''
                for d in data:
                    trueData += chr(d ^ maskingKey[i % 4])
                    i += 1
                return trueData
            else:
                return data

    #废弃
    def recv_data(self):  # 服务器解析浏览器发送的信息
        try:
            all_data = self.con.recv(1024)
            if not len(all_data):
                return False
        except :
            pass
        else:
            code_len = ord(all_data[1]) & 127    #接收的all_data是个bytes，但ord一直报：需要长度为1的字符串，但接收的是整型。百度得知：字节对象就是整数数组，所以这里不能用这个方法解析，弃掉recv_data方法，用readClientData
            if code_len == 126:
                masks = all_data[4:8]
                data = all_data[8:]
            elif code_len == 127:
                masks = all_data[10:14]
                data = all_data[14:]
            else:
                masks = all_data[2:6]
                data = all_data[6:]
            raw_str = ""
            i = 0
            for d in data:
                raw_str += chr(ord(d) ^ ord(masks[i % 4]))
                i += 1
            return raw_str

    #和seng_msg一样都可以用
    def sendDataToClient(self, text):
        sendData = ''
        sendData = struct.pack('!B', 0x81)

        length = len(text)
        if length <= 125:
            sendData += struct.pack('!B', length)
        elif length <= 65536:
            sendData += struct.pack('!B', 126)
            sendData += struct.pack('!H', length)
        elif length == 127:
            sendData += struct.pack('!B', 127)
            sendData += struct.pack('!Q', length)

        sendData += struct.pack('!%ds' % (length), text.encode())
        dataSize = self.con.send(sendData)

    #服务端向客户端发送消息
    def send_msg(self, msg_bytes):
        """
        WebSocket服务端向客户端发送消息
        :param conn: 客户端连接到服务器端的socket对象,即： conn,address = socket.accept()
        :param msg_bytes: 向客户端发送的字节
        :return:
        """
        token = b"\x81"
        length = len(msg_bytes)
        if length < 126:
            token += struct.pack("B", length)
        elif length <= 0xFFFF:
            token += struct.pack("!BH", 126, length)
        else:
            token += struct.pack("!BQ", 127, length)

        msg = token + msg_bytes
        self.con.send(msg)
        return True

    def answer(self, data):
        if (data[0:3] == "TC|"):
            return "hello world"
        elif (data[0:3] == "GS|"):
            return "Gaosi Deblur Survice"
        elif (data[0:3] == "DT|"):
            return "DongTai Deblur Survice"
        else:
            return "Unresolvable Command!"

    def padding(self, data):
        missing_padding = 4 - len(data) % 4
        if missing_padding:
            data += '=' * missing_padding
        return data


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 8003))
    sock.listen(5)
    while True:
        try:
            conn, address = sock.accept()
            returnCrossDomain(conn).start()
        except:
            time.sleep(1)


if __name__ == "__main__":
    main()
