from colours import Colour
from reg import RegexFilters as rf
from clamd import clamdScan as cs
import signal, sys, time, asyncio, shlex, ipaddress, re, socket, os, platform, subprocess

WATCHTIME = 1000
class clientUI():
    def eventHandle(self, sig, frame):
        if self.ssh, self.sVal, self.userDetails in globals() or self.ssh, self.sVal, self.userDetails in locals():
            print(Colour.RED+"Due to a random AudiCrypt closure, a message of this has been sent to the Admin."+Colour.RESET)
            self.tcpClient('unExClose')
        print(Colour.RED + "Clearing all variables..." + Colour.RESET)
        print(Colour.RED + "Exiting AudiCrypt" + Colour.RESET)
        globals().clear()
        print(Colour.GREEN + "Goodbye!" + Colour.RESET)
        sys.quit()

    def hashString(self, string:str):
        from Crypto.Hash import SHA3_256
        self.hashObject = SHA3_256.new(data=string.encode())
        return self.hashObject.hexdigest()

    async def tcpClient(self, mes:str):
        self.mes = mes
        if self.mes == 'getwd':
            try:
                self.reader, self.writer = await asyncio.open_connection(self.ipInput, 8888)
                print(Colour.MAGENTA + f"Connected to {self.ipInput}." + Colour.RESET)
                print(Colour.MAGENTA + f"Sending {self.mes} to {self.ipInput}." + Colour.RESET)
                self.writer.write(self.mes.encode())
                await self.writer.drain()
                self.dat = await self.reader.read(100)
                self.workDir = self.dat.decode()
                print(Colour.MAGENTA + f"Received working directory from {self.ipInput}, closing connection." + Colour.RESET)
                self.writer.close()
                await self.writer.wait_closed()
                return self.workDir
            except Exception as e:
                print(Colour.RED + "Could not connect to Admin, exiting program." + Colour.RESET)
                self.clientUI()
        if self.mes == 'unExClose':
            try:
                self.reader, self.writer = await asyncio.open_connection(self.ipInput, 8888)
                print(Colour.MAGENTA + f"Connected to {self.ipInput}." + Colour.RESET)
                print(Colour.MAGENTA + f"Sending Quit message to {self.ipInput}." + Colour.RESET)
                self.writer.write(self.mes.encode())
                await self.writer.drain()
                self.newDat = await self.reader.read(100)
                self.writer.close()
                await self.writer.wait_closed()
                print(Colour.RED+"Connection to Admin has been closed, quitting AudiCrypt."+Colour.RESET)
                globals().clear();sys.quit()



        else:
            print(Colour.RED + "Unknown error/command, try again." + Colour.RESET)
            return


    def downFile(self,sVal:dict, ud:dict):
        from fabric import Connection
        from invoke import Responder
        self.userDetails = ud
        self.sVal = sVal
        self.ssh = Connection(host=self.sVal['host'], user=self.sVal['u ser'], port=self.sVal['port'],connect_kwargs={"password": self.sVal['pass']})
        while True:
            self.ipInput= input(Colour.MAGENTA + "Enter the IP address of the server: " + Colour.RESET)
            if re.match(rf['ipADDRESS'], self.ipInput):
                while True:
                    try:
                        self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        self.soc.connect(('8.8.8.8', 80))
                        self.ip = self.soc.getsockname()[0]
                    except Exception as e:
                        print(Colour.RED + "Could not test your network connection." + Colour.RESET)
                        self.IP = None
                    finally:
                        self.soc.close()
                        break
                if self.ip != None:
                    self.ipNet = ipaddress.ip_network(self.ip,strict=False)
                    if ipaddress.ip_address(self.ipInput) in self.ipNet:
                        print(Colour.GREEN + "IP address is valid." + Colour.RESET)
                        break
                    else:
                        print(Colour.RED + "IP address is not in your network. Please try again." + Colour.RESET)
                        continue
                else:
                    print(Colour.RED+"Could not test your network connection, please try again."+Colour.RESET)
                    continue
            if not re.match(rf['ipADDRESS'], self.ipInput):
                print(Colour.RED + "Please enter a valid IP address." + Colour.RESET)
                continue
            else:
                print(Colour.RED+"Unknown error with your IP address, please try again."+Colour.RESET)
                continue
        #Now code has broken free of 'while' loop, IP is ready for test.
        time.sleep(WATCHTIME)
        print(Colour.MAGENTA+"You will now be prompted to enter a command to operate this terminal, commands are case-sensitive."+Colour.RESET)
        print(Colour.MAGENTA+"""
        [getWD] - Get working directory from Admin.
        [downFile] - Download a file from the specified working directory.
        [quit] - Quit AudiCrypt.
        
        AudiCrypt does require you view the working directory at least once before downloading a file."""+Colour.RESET)
        while True:
            self.ter = shlex.quote(input(Colour.MAGENTA+"Enter a command: "+Colour.RESET))
            if self.ter == 'getwd':
                #Establishes connection with TCP server (Admin) to get working directory. All AudiCrypt servers will use port 8888.
                print(Colour.MAGENTA+"You have selected to get the working directory from the Admin."+Colour.RESET)
                asyncio.run(self.tcpClient(self.ter))
                print(Colour.MAGENTA+"Working directory set to "+Colour.RED+self.workDir+Colour.MAGENTA+"."+Colour.RESET)
            if self.ter.lower() == 'downfile':
                if self.workDir not in globals() or self.workDir not in locals():
                    print(Colour.RED+"Working directory has not been retrieved. please set it before downloading a file."+Colour.RESET)
                    self.clientUI()
                #Establishes connection with TCP server (Admin) to download a file. All AudiCrypt servers will use port 8888.
                print(Colour.MAGENTA+"You have selected to download a file."+Colour.RESET)
                self.DirecList = ((self.ssh.run(f"ls {self.workDir}",hide=True).stdout.strip()).split('\n'))
                for i in self.direcList:
                    print(Colour.MAGENTA+f"{i}"+Colour.RESET)
                while True:
                    self.fileName = shlex.quote(input(Colour.MAGENTA+"Enter the name of the file you'd like to download: "+Colour.RESET))
                    if self.fileName in self.DirecList:
                        break
                    if self.fileName not in self.DirecList:
                        print(Colour.RED+"File does not exist, please try again."+Colour.RESET)
                        continue
                    else:
                        print(Colour.RED+"Unknown error, please try again."+Colour.RESET)
                        continue
                print(Colour.MAGENTA+"All downloaded files will be stored in a '.audiTemp' folder in your home directory."+Colour.RESET)
                if platform.system() == 'Windows' or platform.system() == 'Linux' or platform.system() == 'Darwin':
                    self.dirPath = os.path.join(os.path.expanduser('~'),'.audiTemp')
                    if os.path.exists(self.dirPath):
                        if os.listdir(os.path.expanduser('~')+'\\.audiTemp') != []:
                            while True:
                                self.delOK = shlex.quote(input(Colour.RED + "Data already exists here, it must be cleaned before connecting to server. Continue? [y/n]" + Colour.RESET))
                                if self.delOK.lower() == 'y' or self.delOK.lower() == 'yes':
                                    for i in os.listdir(os.path.expanduser('~')+'\\.audiTemp'):
                                        os.remove(os.path.expanduser('~')+'\\.audiTemp\\'+i)
                                    break
                                if self.delOK.lower() == 'n' or self.delOK.lower() == 'no':
                                    print(Colour.RED+"Please clean directory, going back to menu."+Colour.RESET)
                                    self.clientUI()
                                else:
                                    print(Colour.RED+"Please enter a valid response."+Colour.RESET)
                                    continue
                    else:
                        os.mkdir(os.path.expanduser('~')+'\\.audiTemp')
                    self.ssh.get(f"{self.workDir}/{self.fileName}",os.path.expanduser('~')+'\\.audiTemp')
                    with open(os.path.expanduser('~')+'\\.audiTemp\\'+self.fileName, 'rb') as f:
                        self.fContents = self.hashString(f.read())
                    print(Colour.MAGENTA+f"File has been downloaded and stored in {os.path.expanduser('~')+'\\.audiTemp'}."+Colour.RESET)
                    if cs.scan(self.workDir+'\\'+self.fileName) == True:
                        print(Colour.GREEN+"File has been scanned and is safe."+Colour.RESET)
                        self.curTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

                        #Take a look at this - how does uKeyID work in this? No identifer at the minute
                        self.ssh.run(f'sudo -u postgres -d audicrypt -c "INSERT INTO cryReceipt (origHash, newHash, fileName, fileLoc) VALUES ({self.fContents}, {self.fContents}, {self.fileName}, {str(self.workDir) + '/' + str(self.fileName)});"')


                        print(Colour.GREEN + "Iniital receipt for: " + Colour.MAGENTA + f"{self.fileName}" + Colour.GREEN + " has been stored." + Colour.RESET)
                        while True:
                            if len(os.listdir(os.path.expanduser('~') + '\\.audiTemp')) == 0:
                                print(Colour.RED + "File has been deleted, going back to menu." + Colour.RESET)
                                self.clientUI()
                            if len(os.listdir(os.path.expanduser('~') + '\\.audiTemp')) > 1:
                                self.fileList = os.listdir(os.path.expanduser('~') + '\\.audiTemp')
                                self.fileList.remove(self.fileName)
                                for i in self.fileList:
                                    if os.path.splitext(i)[1] != '.tmp':
                                        os.remove(os.path.expanduser('~') + '\\.audiTemp\\' + i)
                            self.fsOutput = subprocess.Popen("fswatch -0 " + os.path.expanduser('~') + '\\.audiTemp\\' + self.fileName + " | xargs -n -l{} echo 'DmodF'", shell=True,stdout=subprocess.PIPE)
                            self.output = self.fsOutput.stdout.readline().decode().strip()
                            if self.output == "DmodF":
                                with open(os.path.expanduser('~') + '\\.audiTemp\\' + self.fileName, 'rb') as f:
                                    if cs.scan(self.workDir + '\\' + self.fileName) == True:
                                        print(Colour.GREEN+("File has passed ClamAV Checks."+Colour.RESET))
                                        self.fNewContents = self.hashString(f.read())

                                        #Same issue as earlier mentioned with uKeyID
                                        self.ssh.run(f'sudo -u postgres -d audicrypt -c "INSERT INTO cryReceipt (origHash, newHash, fileName, fileLoc) VALUES ({self.fContents}, {self.fNewContents}, {self.fileName}, {str(self.workDir) + '/' + str(self.fileName)});"')

                                        self.ssh.put(os.path.expanduser('~')+'\\.audiTemp\\'+self.fileName,f"{self.workDir}/{self.fileName}")
                                        print(Colour.MAGENTA + f"New receipt uploaded for {self.fileName} in {self.workDir}" + Colour.RESET)
                                        os.kill(self.fsOutput.pid, signal.SIGTERM)
                                    if cs.scan(self.workDir + '\\' + self.fileName) == False:
                                        print(Colour.RED+"File has been scanned and is not safe, it has been deleted automatically, a receipt of this has been sent to the database for further investigation."+Colour.RESET)
                                        self.fNewContents = self.hashString(f.read())
                                        # Same issue as earlier mentioned with uKeyID
                                        self.ssh.run(f'sudo -u postgres -d audicrypt -c "INSERT INTO cryReceipt (origHash, newHash, fileName, fileLoc) VALUES ({self.fContents}, {self.fNewContents}, {self.fileName}, {str(self.workDir) + '/' + str(self.fileName)});"')

                                        os.remove(os.path.expanduser('~')+'\\.audiTemp\\'+self.fileName)
                                        print(Colour.MAGENTA+"Returning to menu."+Colour.RESET)
                                        self.clientUI()

                                    else:
                                        print(Colour.RED+"Unknown error, please try again."+Colour.RESET)
                                        continue
                    if cs.scan(self.workDir + '\\' + self.fileName) == False:
                        print(Colour.RED+"File has been scanned and is not safe, it has been deleted automatically."+Colour.RESET)
                        os.remove(os.path.expanduser('~')+'\\.audiTemp\\'+self.fileName)
                        print(Colour.MAGENTA+"Returning to menu."+Colour.RESET)
                        self.clientUI()

                    else:
                        print(Colour.RED+"Unknown error, please try again."+Colour.RESET)
                        continue
                        #Functionality to alert Admin of this will come in later stage.
            if self.ter.lower() == 'quit':
                print(Colour.RED+"Quitting AudiCrypt Terminal..."+Colour.RESET)
                self.clientUI()
            else:
                print(Colour.RED+"Please enter a valid command."+Colour.RESET)
                continue

    def deleteProfile(self,sVal:dict, ud:dict):
        from fabric import Connection
        from invoke import Responder
        self.userDetails = ud
        self.ssh = Connection(host=self.sVal['host'], user=self.sVal['user'], port=self.sVal['port'],connect_kwargs={"password": self.sVal['pass']})
        self.sPass = Responder(pattern=r'\[sudo\] password for ' + self.sVal['user'] + ':',response=self.sVal['pass'] + '\n')
        self.sshVal = sVal
        while True:
            self.sureAsk = input(Colour.MAGENTA+ "Are you sure you'd like to delete your AudiCrypt profile? [y/n]" + Colour.RESET)
            if self.sureAsk.lower() == 'y' or self.sureAsk.lower() == 'yes':
                print(Colour.RED + "Deleting AudiCrypt profile..." + Colour.RESET)
                self.getUser = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"SELECT role FROM uCreds WHERE uName = {self.userDetails['user']};\"",hide=True,warn=True,pty=True, watchers=[self.sPass])
                self.getUser = ((((self.getUser.stdout.strip()).replace('-', '')).strip()).split())

                #These two commands get rid of user entirely.

                self.delUser = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"DELETE USER {self.getUser[0]};\"",hide=True,warn=True,pty=True, watchers=[self.sPass])
                self.delUserConfiig = self.ssh.run("sudo -u postgres psql -d audicrypt -c \"DELETE FROM uCreds, uKeys WHERE uName = " + self.userDetails['user'] + ";\"",hide=True,warn=True,pty=True, watchers=[self.sPass])
                if self.delUser.ok and self.delUserConfig.ok:
                    print(Colour.MAGENTA + "AudiCrypt profile has been deleted, goodbye." + Colour.RESET)
                    self.ssh.close()
                    globals().clear()
                    sys.quit()
                else:
                    print(Colour.RED + "AudiCrypt profile could not be deleted, please try again." + Colour.RESET)
                    return
            if self.sureAsk.lower() == 'n' or self.sureAsk.lower() == 'no':
                print(Colour.GREEN + "Great news! Keeping AudiCrypt profile." + Colour.RESET)
                return
            else:
                print(Colour.RED+ "Please enter a valid input." + Colour.RESET)
                continue
    def quitAudiCrypt(self):
        self.sureAsk = input(Colour.MAGENTA + "Are you sure you'd like to quit? [y/n]" + Colour.RESET)
        self.quitTick = False
        while quitTick != True:
            if self.sureAsk.lower() == 'y' or self.sureAsk.lower() == 'yes':
                print(Colour.RED + "Qutting AudiCrypt..." + Colour.RESET)
                self.quitTick = True
            if self.sureAsk.lower() == 'n' or sefl.sureAsk.lower() == 'no':
                print(Colour.GREEN + "Great news! Staying on AudiCrypt." + Colour.RESET)
                self.quitTick = False
                self.adminUI()
            else:
                print(Colour.RED + "Please enter a valid input." + Colour.RESET)
                continue
        globals().clear()
        sys.quit()

    def clientUI(self):
        print(Colour.MAGENTA + "Welcome to AudiCrypt!" + Colour.RESET)
        print(Colour.MAGENTA + "Please wait while we establish a connection to the server..." + Colour.RESET)
        time.sleep(WATCHTIME)
        print(Colour.MAGENTA + "Please note that this is a client-only application." + Colour.RESET)
        time.sleep(WATCHTIME)
        print(Colour.MAGENTA + "To exit, press CTRL+C." + Colour.RESET)
        time.sleep(WATCHTIME)

        print("""
        What would you like to do?
        [1] Download, and work on a file.
        [2] Delete AudiCrypt profile.
        [3] Exit AudiCrypt.""")
    def __init__(self):
        signal.signal(signal.SIGINT, self.eventHandle)
        signal.signal(signal.SIGTERM, self.eventHandle)
        self.clientUI()

if  __name__ == '__main__':
    print(Colour.RED+"This .py file can only be executed as a module, access denied."+Colour.RESET)