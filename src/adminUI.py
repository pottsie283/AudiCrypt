from colours import Colour
import re, sys, signal, socket, asyncio

WATCHTIME = 1000


class adminUI:

   def eventHandle(self,sig, frame):
       print(Colour.RED + "Clearing all variables..."+Colour.RESET)
       print(Colour.RED + "Exiting AudiCrypt" + Colour.RESET)
       if self.server:
          self.server.close()
          asyncio.get_event_loop().run_until_complete(self.server.wait_closed())
       globals().clear()
       print(Colour.GREEN + "Goodbye!" + Colour.RESET)
       sys.quit()
   async def handleClient(self,reader, writer):
       self.reader = reader
       self.writer = writer
       self.data = await self.reader.read(100)
       self.datMessage = self.data.decode()
       self.addr = self.writer.get_extra_info('peername')
       if self.datMessage == "getwd":
           print(Colour.MAGENTA + f"Received Working Directory request from {self.addr}." + Colour.RESET)
           self.writer.write(self.workDir.encode())
           await self.writer.drain()
           self.writer.close()
           await self.writer.wait_closed()
           print(Colour.MAGENTA + f"Sent Working Directory to {self.addr}."+Colour.RESET)

       if self.datMessage == 'unExClose':
           print(Colour.MAGENTA + f"Received request to close from {self.addr}."+Colour.RESET)
           self.writer.write("You have closed your connection to AudiCrypt, this will be investigated.".encode())
           await self.writer.drain()
           self.writer.close()
           await self.writer.wait_closed()

       else:
           print(Colour.RED + f"Received unknown request from {self.addr}."+Colour.RESET)
           self.writer.write("Unknown request, try again.".encode())
           await self.writer.drain()
           self.writer.close()
           await self.write.wait_closed()
   async def runServer(self):
       self.server = await asyncio.start_server(self.handleClient, '127.0.0.1', 8888)
       self.addr = ', '.join(str(sock.getsockname() for sock in self.server.sockets))
       print(Colour.MAGENTA+"Server running on "+self.addr+'.'+Colour.RESET)
       async with self.server:
           await self.server.serve_forever()
   def establishLink(self,sVal:dict):
       from twisted.internet.protocol import Protocol, Factory
       #from twisted.internet.endpoints import TCP4ClientEndpoint
       #qfrom twisted.internet import reactor

       #'twisted' is just WAY too hard to understand, going to use asyncio (with a hint of sockets included in its source code I think? >:(
       self.sVal = sVal
       if self.com in globals() or self.com in locals():
           asyncio.run(self.runServer())
       else:
           print(Colour.RED + "Please set the working directory first."+Colour.RESET)
           self.getDic(self.sVal)
           self.establishLink(self.sVal)
   def getDic(self,sVal:dict):
       self.sVal = sVal
       from fabric import Connection
       from invoke import Responder
       import shlex
       print(Colour.MAGENTA + "Choosing Working directory. "+Colour.RESET)
       self.ssh = Connection(host=self.sVal['host'], user=self.sVal['user'], port=self.sVal['port'], connect_kwargs={"password": self.sVal['pass']})
       self.sPass = Responder(pattern=r'\[sudo\] password for '+self.sVal['user']+':', response=self.sVal['pass']+'\n')
       while True:
           self.com = shlex.quote(input(Colour.MAGENTA + "Enter the path to the working directory: "+Colour.RESET))
           self.filePathReg = r'^.*/[^/]*$'
           if re.match(self.filePathReg, self.com):
                self.checkDir = self.ssh.run(f"test -d {self.com} && echo 'Directory exists' || echo 'Directory does not exist'", hide=True,watchers=[self.sPass])
                if self.checkDir.stdout == "Directory exists\n":
                    print(Colour.MAGENTA+ "Directory exists!"+Colour.RESET)
                    self.ssh.run(f'cd {self.com}', hide=True,watchers=[self.sPass])
                    self.hap = input(Colour.MAGENTA + f"Are you happy with {self.ssh.run(f'cd {self.com} && pwd', watchers=[self.sPass]).stdout.strip()}? [y/n] "+Colour.RESET)
                if self.hap.lower() == "y" or self.hap.lower() == 'yes':
                    print(Colour.GREEN + "Working directory set successfully!"+Colour.RESET)
                    break
                else:
                    print(Colour.RED + "Directory does not exist, please try again."+Colour.RESET)
           else:
                print(Colour.RED + "Please insert a valid directory path."+Colour.RESET)
                continue
       self.workDir = self.ssh.run(f'cd {self.com} && pwd', hide=True,watchers=[self.sPass]).stdout.strip()
       self.ssh.close()
       return self.workDir
   def refreshLoop(self):
       #Requires modification once receipts are actually being stored.
       for i in self.tree.get_children():
           self.tree.delete(i)
       self.dat = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"SELECT * FROM \"cryReceipt\";\"",hide=True,warn=True,pty=True, watchers=[self.sPass])
       for i in self.dat.stdout.split("\n")[2:-2]:
           self.tree.insert("", "end", values=i.split("|"))
       self.root.after(WATCHTIME, self.refreshLoop)
   def viewLog(self,sVal:dict):
       self.sVal = sVal
       from fabric import Connection
       from invoke import Responder
       import tkinter as tk
       from tkinter import ttk
       print(Colour.MAGENTA + "Viewing Receipt log. "+Colour.RESET)
       self.ssh = Connection(host=self.sVal['host'], user=self.sVal['user'], port=self.sVal['port'], connect_kwargs={"password": self.sVal['pass']})
       self.sPass = Responder(pattern=r'\[sudo\] password for '+self.sVal['user']+':', response=self.sVal['pass']+'\n')
       self.datColumns = ['id', 'timestamp', 'uKeyID', 'origHash', 'newHash', 'fileName', 'fileLoc']
       self.root = tk.Tk()
       self.root.title("AudiCrypt Receipt Log")
       self.tree = ttk.Treeview(self.root)
       self.tree.pack()
       self.tree['columns'] = self.datColumns
       for i in range(len(self.datColumns)):
           self.tree.column(self.datColumns[i], width=100,anchor=tk.W)
           self.tree.heading(self.datColumns[i], text=self.datColumns[i])
       self.refreshLoop()
       self.root.mainloop()
   def delConfig(self,sVal:dict):
       self.sureAsk = input(Colour.MAGENTA+"Are you sure you'd like to "+Colour.RED+"DELETE"+Colour.MAGENTA+" AudiCrypt?")
       self.ssh = Connection(host=self.sVal['host'], user=self.sVal['user'], port=self.sVal['port'],connect_kwargs={"password": self.sVal['pass']})
       self.sPass = Responder(pattern=r'\[sudo\] password for ' + self.sVal['user'] + ':',response=self.sVal['pass'] + '\n')
       while True:
           if self.sureAsk.lower() == 'y' or self.sureAsk.lower() == 'yes':
               print(Colour.RED+"Deleting AudiCrypt..."+Colour.RESET)
               self.ssh.run("sudo -u postgres psql -c \"DROP ROLE audiadmin;\"",hide=True,warn=True,pty=True, watchers=[self.sPass])
               self.ssh.run("sudo -u postgres psql -c \"DROP ROLE audiuser;\"",hide=True,warn=True,pty=True, watchers=[self.sPass])
               self.userVal = self.ssh.run('sudo -u postgres psql -c "\\du"',hide=True,warn=True,pty=True, watchers=[self.sPass]).stdout.strip()
               self.userVal.split("\n")
               for l in line:
                   self.pa = line.split("|")
                   if len(self.pa) == 2:
                       self.rolName = self.pa[0].strip()
                       if self.rolName.startswith("audi"):
                           self.ssh.run(f"sudo -u postgres psql -c \"DROP ROLE {self.rolName};\"",hide=True,warn=True,pty=True, watchers=[self.sPass])
               self.delDat = self.ssh.run("sudo -u postgres psql -c \"DROP DATABASE audicrypt;\"",hide=True,warn=True,pty=True, watchers=[self.sPass])
               if self.delDat.ok:
                   print(Colour.MAGENTA+"AudiCrypt has been deleted, goodbye."+Colour.RESET)
                   self.ssh.close()
                   globals().clear()
                   sys.quit()
               else:
                   print(Colour.RED+"AudiCrypt could not be deleted, please try again."+Colour.RESET)
                   self.adminUI()

           if self.sureAsk.lower() == 'n' or self.sureAsk.lower() == 'no':
               print(Colour.GREEN+"Great news! Keeping AudiCrypt."+Colour.RESET)
               self.adminUI()
           else:
               print(Colour.RED+"Please enter a valid input."+Colour.RESET)
               continue
   def quitAudiCrypt(self):
       #Modify further when clients are connected, to disconnect them once news of this has reached them.
       self.sureAsk = input(Colour.MAGENTA+"Are you sure you'd like to quit? [y/n]"+Colour.RESET)
       self.quitTick = False
       while quitTick != True:
           if self.sureAsk.lower() == 'y' or self.sureAsk.lower() == 'yes':
               print(Colour.RED+"Qutting AudiCrypt..."+Colour.RESET)
               self.quitTick = True
           if self.sureAsk.lower() == 'n' or sefl.sureAsk.lower() == 'no':
               print(Colour.GREEN+"Great news! Staying on AudiCrypt."+Colour.RESET)
               self.quitTick = False
               self.adminUI()
           else:
               print(Colour.RED+"Please enter a valid input."+Colour.RESET)
               continue
       globals().clear()
       sys.quit()


   def adminUI(self):
       print(Colour.MAGENTA + """
       Welcome to the AudiCrypt Admin Panel!
       
       What would you like to do?
       [1] Get working directory
       [2] View Receipt log
       [3] Delete AudiCrypt config
       [4[ Quit AudiCrypt
       [5] Establish server connection
       """)
   def __init__(self):
       signal.signal(signal.SIGINT, self.eventHandle)
       signal.signal(signal.SIGTERM, self.eventHandle)
       self.adminUI()

if  __name__ == '__main__':
    print(Colour.RED+"This .py file can only be executed as a module, access denied."+Colour.RESET)