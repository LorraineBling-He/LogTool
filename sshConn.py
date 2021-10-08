import paramiko


class SSHConn():
    def __init__(self):
        self.ssh = paramiko.SSHClient()

    def get_ssh(self, ip, user, pwd, port=22):
        try:
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(ip, port, user, pwd, timeout=15)
            return self.ssh
        except Exception as e:
            print(e)
            return "False"
            self.ssh.connect(ip, 22, user, pwd, timeout=15)

    # def connect(self):
    #     transport = paramiko.Transport(('172.16.201.71', 22))
    #     transport.connect(username='root', password='xtptbim@2018')
    #     self.ssh._transport = transport
    #     return self.ssh

    def exec(self, command):
        self.ssh.exec_command(command)

    def exec_command(self, command):
        stdin, stdout, stderr = self.ssh.exec_command(command)
        result = stdout.read().decode("utf-8")
        return result

    def closeConnect(self):
        self.ssh._transport.close()
