import base64
import hashlib
import struct

import socket


class WebConn():
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def socket_connect(self):
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 8003))
        self.sock.listen(5)
        # 等待用户连接
        conn, address = self.sock.accept()
        # 握手
        self.handshake(conn)
        return conn

    def handshake(self, conn):
        data = conn.recv(8026)
        headers = self.get_headers(data)
        value = headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        ac = base64.b64encode(hashlib.sha1(value.encode('utf-8')).digest())
        response_tpl = "HTTP/1.1 101 Switching Protocols\r\n" \
                       "Upgrade:websocket\r\n" \
                       "Connection:Upgrade\r\n" \
                       "Sec-WebSocket-Accept:%s\r\n" \
                       "WebSocket-Location:ws://%s%s\r\n\r\n"
        response_str = response_tpl % (ac.decode('utf-8'), headers['Host'], headers['url'])
        conn.send(bytes(response_str, encoding='utf-8'))

    def get_headers(self, data):
        """
        将请求头格式化成字典
        :param data:
        :return:
        """
        header_dict = {}
        data = str(data, encoding='utf-8')

        header, body = data.split('\r\n\r\n', 1)
        header_list = header.split('\r\n')
        for i in range(0, len(header_list)):
            if i == 0:
                if len(header_list[i].split(' ')) == 3:
                    header_dict['method'], header_dict['url'], header_dict['protocol'] = header_list[i].split(' ')
            else:
                k, v = header_list[i].split(':', 1)
                header_dict[k] = v.strip()
        return header_dict

    def send_msg(self, conn, msg_bytes):
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
        conn.send(msg)
        return True

    def readClientData(self,conn):
        if self.masking == 1:
            maskingKey = conn.recv(4)
        data = conn.recv(self.payDataLength)

        if self.masking == 1:
            i = 0
            trueData = ''
            for d in data:
                trueData += chr(d ^ maskingKey[i % 4])
                i += 1
            return trueData
        else:
            return data

    def getDataLength(self,conn):
        second8Bit = conn.recv(1)
        second8Bit = struct.unpack('B', second8Bit)[0]
        masking = second8Bit >> 7
        dataLength = second8Bit & 0b01111111
        #print("dataLength:",dataLength)
        if dataLength <= 125:
            payDataLength = dataLength
        elif dataLength == 126:
            payDataLength = struct.unpack('H', self.con.recv(2))[0]
        elif dataLength == 127:
            payDataLength = struct.unpack('Q', self.con.recv(8))[0]
        self.masking = masking
        self.payDataLength = payDataLength
