import ipaddress
import os, sys, subprocess, re, time, signal
from tqdm import tqdm
from colours import Colour
from reg import RegexFilters as rf
from secQ import SecurityQuestion as sq
class Constants():
    SLEEPTIME = 1
    AUDICRYPT_TABLES = ['uKeys','userCreds','cryReceipt']
    HIDE = True

class UserUI():
    def signalHandler(self,sig, frame):
        import sys
        print(Colour.RED + "Clearing all variables." + Colour.RESET)
        print(Colour.RED + "Exiting AudiCrypt." + Colour.RESET)
        time.sleep(Constants.SLEEPTIME)
        print(Colour.GREEN+"Goodbye!"+Colour.RESET)
        globals().clear()
        sys.exit(0)
    def checkDependencies(self):
        import pkg_resources as pk
        self.reqPackages = ["pycryptodomex","pyclamd","pycryptodome","nuitka","numba","twisted","pyftpdlib","clamd","asyncio","fswatch","psycopg2-binary","kivy","PyQt5","paramiko","fabric","invoke"]
        self.installedPackages = pk.working_set
        self.installedPackagesSet = sorted(["%s" % (i.key) for i in self.installedPackages])
        for package in tqdm(self.reqPackages, desc="Checking packages", unit="package"):
            if package not in self.installedPackagesSet:
                print(Colour.RED + package + " is not installed. Installing..." + Colour.RESET)
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print(Colour.GREEN + "All required packages are installed." + Colour.RESET)

    def checkAV(self):
        try:
            self.oPut = subprocess.check_output(["clamscan", "--version"])
            if "ClamAV" in self.oPut.decode():
                print(Colour.GREEN + "ClamAV detected." + Colour.RESET)
                return
            else:
                print(Colour.RED + "ClamAV not detected." + Colour.RESET)
                return
        except:
            print(Colour.RED + "ClamAV not detected." + Colour.RESET)
            return
    def hashString(self, string):
        from Crypto.Hash import SHA3_256
        self.hashObject = SHA3_256.new(data=string.encode())
        return self.hashObject.hexdigest()

    def hashStringExDigest(self, string):
        from Crypto.Hash import SHA3_256
        self.hashObject = SHA3_256.new(data=string.encode())
        return self.hashObject

    def curUser(self):
        print(Colour.MAGENTA + "Welcome to AudiCrypt, let's get you logged in!" + Colour.RESET)
        while True:
            self.rs = input(Colour.MAGENTA + "Enter a role (Admin/Client): " + Colour.RESET)
            if self.rs.lower() == "admin" or self.rs.lower() == "a":
                print(Colour.GREEN + "Admin role selected." + Colour.RESET)
                break
            if self.rs.lower() == "client" or self.rs.lower() == "c":
                print(Colour.GREEN + "Client role selected." + Colour.RESET)
                break
            else:
                print(Colour.RED + "Invalid role. Please try again." + Colour.RESET)
        self.userDetails = {}
        while True:
            self.userName = input(Colour.MAGENTA + "Enter a username: " + Colour.RESET)
            self.reg = rf.regFilters['username']
            if isinstance(self.userName, str) == False:
                print(Colour.RED + "Username must be a String." + Colour.RESET)
                continue
            if not self.userName:
                print(Colour.RED + "Username cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.userName):
                print(
                    Colour.RED + "Username must contain at least 1 lowercase, 1 uppercase, 1 digit, 1 special character, and be 8 characters long." + Colour.RESET)
                continue
            print(Colour.GREEN + "Username is valid." + Colour.RESET)
            self.userDetails['UN'] = self.hashString(self.userName)
            break

        while True:
            self.passWord = input(Colour.MAGENTA + "Enter a password: " + Colour.RESET)
            self.reg = rf.regFilters['password']
            if isinstance(self.passWord, str) == False:
                print(Colour.RED + "Password must be a String." + Colour.RESET)
                continue
            if not self.passWord:
                print(Colour.RED + "Password cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.passWord):
                print(
                    Colour.RED + "Password must contain at least 1 lowercase, 2 uppercase, 2 special characters, and be 12-20 characters long." + Colour.RESET)
                continue
            print(Colour.GREEN + "Password is valid." + Colour.RESET)
            self.userDetails['PW'] = self.hashString(self.passWord)
            break

        self.printSec()

        while True:
            self.securityQuestionNumber = input(Colour.MAGENTA + "Enter a security question number: " + Colour.RESET)
            if self.securityQuestionNumber not in sq.securityList():
                print(Colour.RED + "Invalid security question number." + Colour.RESET)
                continue
            print(Colour.GREEN + "Security question is valid." + Colour.RESET)
            self.userDetails['SQ1C'] = self.hashString(sq.securityList()[self.securityQuestionNumber])
            break

        while True:
            self.secQuestionAnswer = input(Colour.MAGENTA + "Enter a security question answer: " + Colour.RESET)
            self.reg = rf.regFilters['security']
            if isinstance(self.secQuestionAnswer, str) == False:
                print(Colour.RED + "Security question must be a String." + Colour.RESET)
                continue
            if not self.secQuestionAnswer:
                print(Colour.RED + "Security question cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.secQuestionAnswer):
                print(
                    Colour.RED + "Security question must contain at least 1 uppercase letter, and be at least 5 characters long." + Colour.RESET)
                continue
            print(Colour.GREEN + "Security question is valid." + Colour.RESET)
            self.userDetails['SQ1A'] = self.hashString(self.secQuestionAnswer)
            break

        self.printSec()

        while True:
            self.securityQuestionNumber = input(Colour.MAGENTA + "Enter a security question number: " + Colour.RESET)
            if self.securityQuestionNumber not in sq.securityList():
                print(Colour.RED + "Invalid security question number." + Colour.RESET)
                continue
            print(Colour.GREEN + "Security question is valid." + Colour.RESET)
            self.userDetails['SQ2C'] = self.hashString(sq.securityList()[self.securityQuestionNumber])
            break

        while True:
            self.secQuestionAnswer = input(Colour.MAGENTA + "Enter a security question answer: " + Colour.RESET)
            self.reg = rf.regFilters['security']
            if isinstance(self.secQuestionAnswer, str) == False:
                print(Colour.RED + "Security question must be a String." + Colour.RESET)
                continue
            if not self.secQuestionAnswer:
                print(Colour.RED + "Security question cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.secQuestionAnswer):
                print(
                    Colour.RED + "Security question must contain at least 1 uppercase letter, and be at least 5 characters long." + Colour.RESET)
                continue
            print(Colour.GREEN + "Security question is valid." + Colour.RESET)
            self.userDetails['SQ2A'] = self.hashString(self.secQuestionAnswer)
            break

        while True:
            self.fullName = input(Colour.MAGENTA + "Enter your full name: " + Colour.RESET)
            self.reg = rf.regFilters['fullName']
            if isinstance(self.fullName, str) == False:
                print(Colour.RED + "Full Name must be a String." + Colour.RESET)
                continue
            if not self.fullName:
                print(Colour.RED + "Full Name cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.fullName):
                print(
                    Colour.RED + "Full Name must contain only letters and be in the format: First Last" + Colour.RESET)
                continue
            print(Colour.GREEN + "Full Name is valid." + Colour.RESET)
            self.userDetails['FN'] = self.hashString(self.fullName)
            break
        print(Colour.GREEN + "Thank you for inputting your details." + Colour.RESET)
        if self.rs.lower() == "admin" or self.rs.lower() == "a":
            self.verifyLogin("admin")
        if self.rs.lower() == "client" or self.rs.lower() == "c":
            self.verifyLogin("client")

    def verifyLogin(self,vType):
        from fabric import Connection
        from invoke import Responder
        self.vType = vType
        if self.vType == "admin":
            print(Colour.MAGENTA+"AudiCrypt will now verify your login details."+Colour.RESET)
            self.sshVal = {}
            while True:
                while True:
                    self.host = input(Colour.MAGENTA + "Enter the IP (IPv4) address of your server: " + Colour.RESET)
                    self.reg = rf.regFilters['ipADDRESS']
                    if re.match(self.reg, self.host):
                        print(Colour.GREEN + "IP address is valid." + Colour.RESET)
                        self.sshVal['host'] = self.host
                        break
                    if not re.match(self.reg, self.host):
                        print(Colour.RED + "Invalid IP address. Please try again." + Colour.RESET)
                        continue
                    else:
                        print(Colour.RED + "Invalid value, please try again." + Colour.RESET)

                while True:
                    self.port = input(Colour.MAGENTA + "Enter the SSH port of your server: " + Colour.RESET)
                    self.reg = rf.regFilters['portSSH']
                    if re.match(self.reg, self.port):
                        print(Colour.GREEN + "Port is valid." + Colour.RESET)
                        self.sshVal['port'] = self.port
                        break
                    if not re.match(self.reg, self.port):
                        print(Colour.RED + "Invalid port. Please try again." + Colour.RESET)
                        continue
                    else:
                        print(Colour.RED + "Invalid value, please try again." + Colour.RESET)
                        continue

                while True:
                    self.user = input(Colour.MAGENTA + "Enter the username of your server: " + Colour.RESET)
                    if not self.user:
                        print(Colour.RED + "Username cannot be empty." + Colour.RESET)
                        continue
                    print(Colour.GREEN + "Username is valid." + Colour.RESET)
                    self.sshVal['user'] = self.user
                    break

                while True:
                    self.pwd = input(Colour.MAGENTA + "Enter the password of your server: " + Colour.RESET)
                    if not self.pwd:
                        print(Colour.RED + "Password cannot be empty." + Colour.RESET)
                        continue
                    print(Colour.GREEN + "Password is valid." + Colour.RESET)
                    self.sshVal['pass'] = self.pwd
                    break
                break
            self.ssh = Connection(self.sshVal['host'], user=self.sshVal['user'], port=self.sshVal['port'],connect_kwargs={"password": self.sshVal['pass']})
            self.sPass = Responder(pattern=r'\[sudo\] password for ' + self.sshVal['user'] + ':',response=f'{self.sshVal["pass"]}\n')
            self.qPass = Responder(pattern=r'\(END\)',response='q\n')
            self.audiExist = self.verifyAudiCryptExists()
            if self.audiExist == True:
                print(Colour.GREEN + "AudiCrypt database found." + Colour.RESET)
                self.audiTables = self.audiTableCheck()
                if self.audiTables == True:
                    print(Colour.MAGENTA + "AudiCrypt tables not found." + Colour.RESET)
                    print(Colour.RED+"There is an error with the AudiCrypt database, restart the program, make a new Admin account, and make a new database."+Colour.RESET)
                    self.ssh.close()
                    self.checkLog()
                if self.audiTables == False:
                    self.vUser = ['name','uName','pWord','sQ1C','sQ1A','sQ2C','sQ2A']
                    self.uDetailKey = ['FN','UN','PW','SQ1C','SQ1A','SQ2C','SQ2A']
                    self.uDetailKeyPrint = ['First Name', 'Username', 'Password', 'Security Question 1', 'Security Question 1 Answer', 'Security Question 2', 'Security Question 2 Answer']
                    self.comp = False
                    for i in range(len(self.vUser)):
                        self.vUserExec = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"SELECT {self.vUser[i]} FROM uCreds WHERE uName = '{self.userDetails['UN']}';\"", hide=True,pty=True, watchers=[self.sPass])
                        self.vUserExec = ((((self.vUserExec.stdout.strip()).replace('-','')).strip()).split())
                        if self.userDetails[f'{self.uDetailKey[i]}'] in self.vUserExec[5]:
                            self.comp = True
                        else:
                            print(Colour.RED + f"{self.uDetailKeyPrint[i]} not verified, there is an error with your AudiCrypt configuration. Returning to the menu. You might not have put the right details in?" + Colour.RESET)
                            self.ssh.close()
                            self.checkLog()
                    if self.comp == True:
                        self.comp = False
                        print(Colour.GREEN + "All Admin details verified." + Colour.RESET)
                        while True:
                            self.inpPrKey = self.hashString(input(Colour.MAGENTA + "Enter your Private Key: " + Colour.RESET))
                            self.prKeyExec = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"SELECT prKey FROM uKeys WHERE userCredID = (SELECT id FROM uCreds WHERE uName = '{self.userDetails['UN']}');\"", hide=True,pty=True, watchers=[self.sPass])
                            self.prKeyExec = ((((self.prKeyExec.stdout.strip()).replace('-','')).strip()).split())
                            if self.inpPrKey in self.prKeyExec:
                                self.comp = True
                                break
                            else:
                                print(Colour.RED + "Private Key not verified." + Colour.RESET)
                                continue
                        if self.comp == True:
                            print(Colour.GREEN + "Private Key verified." + Colour.RESET)
                            print(Colour.MAGENTA + f"AudiCrypt login complete. Welcome {(self.fullName.split())[0]}!"+Colour.RESET)
                            self.ssh.close()
                            import adminUI as aUI
                            while True:
                                aUI.adminUI()
                                self.answer = input(Colour.MAGENTA + "Enter an option: " + Colour.RESET)
                                if self.answer == "1":
                                    self.workDir = aUI.adminUI().getDic(self.sshVal)
                                if self.answer == "2":
                                    aUI.adminUI().viewLog(self.sshVal)
                                if self.answer == "3":
                                    aUI.adminUI().delConfig(self.sshVal)
                                if self.answer == "4":
                                    aUI.adminUI().quitAudiCrypt()
                                if self.answer == "5":
                                    aUI.adminUI().establishLink(self.sshVal)
                                else:
                                    print(Colour.RED + "Invalid option. Please try again." + Colour.RESET)
                                    continue

                    else:
                        print(Colour.RED + "Admin details not verified." + Colour.RESET)
                        self.ssh.close()
                        self.checkLog()
            if self.audiExist == False:
                print(Colour.RED + "AudiCrypt database not found." + Colour.RESET)
                self.ssh.close()
                print(Colour.RED+"There is an error with the AudiCrypt database, restart the program, make a new Admin account, and make a new database."+Colour.RESET)
                self.checkLog()

        if self.vType == 'client':
            print(Colour.MAGENTA+"AudiCrypt will now verify your login details."+Colour.RESET)
            self.sshVal = {}
            while True:
                while True:
                    self.host = input(Colour.MAGENTA + "Enter the IP (IPv4) address of your server: " + Colour.RESET)
                    self.reg = rf.regFilters['ipADDRESS']
                    if re.match(self.reg, self.host):
                        print(Colour.GREEN + "IP address is valid." + Colour.RESET)
                        self.sshVal['host'] = self.host
                        break
                    if not re.match(self.reg, self.host):
                        print(Colour.RED + "Invalid IP address. Please try again." + Colour.RESET)
                        continue
                    else:
                        print(Colour.RED + "Invalid value, please try again." + Colour.RESET)

                while True:
                    self.port = input(Colour.MAGENTA + "Enter the SSH port of your server: " + Colour.RESET)
                    self.reg = rf.regFilters['portSSH']
                    if re.match(self.reg, self.port):
                        print(Colour.GREEN + "Port is valid." + Colour.RESET)
                        self.sshVal['port'] = self.port
                        break
                    if not re.match(self.reg, self.port):
                        print(Colour.RED + "Invalid port. Please try again." + Colour.RESET)
                        continue
                    else:
                        print(Colour.RED + "Invalid value, please try again." + Colour.RESET)
                        continue

                while True:
                    self.user = input(Colour.MAGENTA + "Enter the username of your server: " + Colour.RESET)
                    if not self.user:
                        print(Colour.RED + "Username cannot be empty." + Colour.RESET)
                        continue
                    print(Colour.GREEN + "Username is valid." + Colour.RESET)
                    self.sshVal['user'] = self.user
                    break

                while True:
                    self.pwd = input(Colour.MAGENTA + "Enter the password of your server: " + Colour.RESET)
                    if not self.pwd:
                        print(Colour.RED + "Password cannot be empty." + Colour.RESET)
                        continue
                    print(Colour.GREEN + "Password is valid." + Colour.RESET)
                    self.sshVal['pass'] = self.pwd
                    break
                break
            self.ssh = Connection(self.sshVal['host'], user=self.sshVal['user'], port=self.sshVal['port'],connect_kwargs={"password": self.sshVal['pass']})
            self.sPass = Responder(pattern=r'\[sudo\] password for ' + self.sshVal['user'] + ':',response=f'{self.sshVal["pass"]}\n')
            self.qPass = Responder(pattern=r'\(END\)', response='q\n')
            self.audiExist = self.verifyAudiCryptExists()
            if self.audiExist == True:
                print(Colour.GREEN + "AudiCrypt database found." + Colour.RESET)
                self.audiTables = self.audiTableCheck()
                if self.audiTables == True:
                    print(Colour.MAGENTA + "AudiCrypt tables not found." + Colour.RESET)
                    print(
                        Colour.RED + "There is an error with the AudiCrypt database. Your admin must restart AudiCrypt confiiguration." + Colour.RESET)
                    self.ssh.close()
                    self.checkLog()
                if self.audiTables == False:
                    self.vUser = ['name', 'uName', 'pWord', 'sQ1C', 'sQ1A', 'sQ2C', 'sQ2A']
                    self.uDetailKey = ['FN', 'UN', 'PW', 'SQ1C', 'SQ1A', 'SQ2C', 'SQ2A']
                    self.uDetailKeyPrint = ['First Name', 'Username', 'Password', 'Security Question 1',
                                            'Security Question 1 Answer', 'Security Question 2',
                                            'Security Question 2 Answer']
                    self.comp = False
                    for i in range(len(self.vUser)):
                        self.vUserExec = self.ssh.run(
                            f"sudo -u postgres psql -d audicrypt -c \"SELECT {self.vUser[i]} FROM uCreds WHERE uName = '{self.userDetails['UN']}';\"",
                            hide=True, pty=True, watchers=[self.sPass])
                        self.vUserExec = ((((self.vUserExec.stdout.strip()).replace('-', '')).strip()).split())
                        if self.userDetails[f'{self.uDetailKey[i]}'] in self.vUserExec[5]:
                            self.comp = True
                        else:
                            print(
                                Colour.RED + f"{self.uDetailKeyPrint[i]} not verified, there is an error with your AudiCrypt configuration. Returning to the menu. You might not have put the right details in?" + Colour.RESET)
                            self.ssh.close()
                            self.checkLog()
                    if self.comp == True:
                        self.comp = False
                        print(Colour.GREEN + "All Client details verified." + Colour.RESET)
                        while True:
                            self.inpPrKey = self.hashString(
                                input(Colour.MAGENTA + "Enter your Private Key: " + Colour.RESET))
                            self.prKeyExec = self.ssh.run(
                                f"sudo -u postgres psql -d audicrypt -c \"SELECT prKey FROM uKeys WHERE userCredID = (SELECT id FROM uCreds WHERE uName = '{self.userDetails['UN']}');\"",
                                hide=True, pty=True, watchers=[self.sPass])
                            self.prKeyExec = ((((self.prKeyExec.stdout.strip()).replace('-', '')).strip()).split())
                            if self.inpPrKey in self.prKeyExec:
                                self.comp = True
                                break
                            else:
                                print(Colour.RED + "Private Key not verified." + Colour.RESET)
                                continue
                        if self.comp == True:
                            print(Colour.GREEN + "Private Key verified." + Colour.RESET)
                            print(
                                Colour.MAGENTA + f"AudiCrypt login complete. Welcome {(self.fullName.split())[0]}!" + Colour.RESET)
                            self.ssh.close()
                            import clientUI as cUI
                            while True:
                                cUI.clientUI()
                                self.answer = input(Colur.MAGENTA + "Enter an option: " + Colour.RESET)
                                if self.answer == '1':
                                    print(Colour.MAGENTA+"You have selected to download, and work on a file."+Colour.RESET)
                                    cUI.ClientUI.downFile(self.sshVal,self.userDetails)
                                if self.answer == '2':
                                    print(Colour.MAGENTA+"You have selected to delete your AudiCrypt profile."+Colour.RESET)
                                    cUI.CLineUI().deleteProfile(self.sshVal,self.userDetails)
                                if self.answer == '3':
                                    print(Colour.MAGENTA+"You have selected to exit AudiCrypt."+Colour.RESET)
                                    cUI.ClientUI().quitAudiCrypt()
                                else:
                                    print(Colour.RED+ "Invalid option. Please try again." + Colour.RESET)

                    else:
                        print(Colour.RED + "Client details not verified." + Colour.RESET)
                        self.ssh.close()
                        self.checkLog()
            if self.audiExist == False:
                print(Colour.RED + "AudiCrypt database not found." + Colour.RESET)
                self.ssh.close()
                print(
                    Colour.RED + "There is an error with the AudiCrypt database. Ask your Admin to restart AudiCrypt confiiguration." + Colour.RESET)
                self.checkLog()

            

    def adInitTableUpdate(self):
        #All values MUST be hashed with SHA3-256 before being inserted into the database.
        #Insert all Admin details into the new database for the first time.

        #To avoid confusion - the public key is NOT HASHED, the private key is HASHED, and the RSA signature is also HASHED.
        #This is to ensure that the data is secure, and cannot be tampered with.
        #This relies on a user having a secure password, and secure security questions. This is regulated by regex in 'reg.py'.
        #The public key is stored in plaintext, as it is required for encryption/decryption.
        #This also relies on the user storing their private key, and RSA signature in a secure location.
        #When a user logs in, their public key is checked against a hash in the database.
        #If the hash matches, the user is authenticated. If not, the user is denied access.

        #Since the user has their private key, this will be kept securely stored in memory.
        #Since only the admin has read access to the cryReceipt table, no one can read a user's signature either. Users can only write to this table.
        #The admin can read the table, and verify the signature against the hash in the database.


        self.uCredInsert = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"INSERT INTO uCreds (name, uName, pWord, sQ1C, sQ1A, sQ2C, sQ2A) VALUES ('{self.userDetails['FN']}','{self.userDetails['UN']}', '{self.userDetails['PW']}','{self.userDetails['SQ1C']}', '{self.userDetails['SQ1A']}', '{self.userDetails['SQ2C']}', '{self.userDetails['SQ2A']}');\"",warn=True, pty=True, watchers=[self.sPass])
        if self.uCredInsert.ok:
            time.sleep(Constants.SLEEPTIME)
            print(Colour.GREEN + "Admin details inserted into uCreds." + Colour.RESET)
            self.puKeyStripped = self.puKey.replace("-----BEGIN PUBLIC KEY-----", "")
            self.puKeyStripped = self.puKeyStripped.replace("-----END PUBLIC KEY-----", "")
            self.puKeyStripped = str(self.puKeyStripped.strip())
            self.prKeyStripped = str(self.prKey)
            self.prKeyStripped = (self.prKeyStripped.split("-----BEGIN RSA PRIVATE KEY-----"))[1].split(
                '-----END RSA PRIVATE KEY-----')
            self.prKeyStripped = str(self.prKeyStripped[0])
            print(
                Colour.RED + "\n\nPLEASE MEMORISE/KEEP A NOTE OF YOUR PRIVATE KEY. YOU WILL REQUIRE THIS FOR LOGIN." + Colour.RESET)
            time.sleep(Constants.SLEEPTIME+3)
            print(Colour.MAGENTA + self.prKeyStripped + '\n' + Colour.RESET)
            self.prKeyStripEnc = self.hashString(self.prKeyStripped)
            print(Colour.GREEN + "Uploading your Admin Keys to AudiCrypt database.")
            self.puKeyUpload = self.ssh.run("sudo -u postgres psql -d audicrypt -c \"INSERT INTO uKeys (userCredID, puKey, prKey) VALUES ((SELECT id FROM uCreds WHERE uName = '" +self.userDetails['UN']+"'), '" + self.puKeyStripped + "', '" + self.prKeyStripEnc + "');\"", warn=True, pty=True, watchers=[self.sPass])
            if self.puKeyUpload.ok:
                print(Colour.MAGENTA + 'Public, and Private key key uploaded to database.' + Colour.RESET)
                time.sleep(Constants.SLEEPTIME)
                return True
            else:
                print(Colour.RED + 'Public/Private key upload failed.' + Colour.RESET)
                self.ssh.close()
                return False
        else:
            print(Colour.RED + "Error with inserting Admin details into uCreds." + Colour.RESET)
            self.ssh.close()
            return False

    def adTableManip(self):
        try:
            # Manipulating a few parameters of the AudiCrypt tables to ensure no unauthorised access.
            # This is to ensure that only the admin can read the cryReceipt table, and only the admin can write to the uKeys table.
            # This is to ensure that the integrity of the AudiCrypt database is not compromised.
            print(Colour.MAGENTA + "Altering table permissions, making a new Admin role." + Colour.RESET)
            self.roles = ['audiadmin','audiuser']
            self.rolResult = self.ssh.run("sudo -u postgres psql -c \"SELECT rolname FROM pg_catalog.pg_roles;\"", hide=True, pty=True, watchers=[self.sPass])
            self.rolResult = self.rolResult.stdout.split("\n")[2:-3]
            self.extNames = [role.strip() for role in self.rolResult if role.strip() in self.roles]
            print(self.extNames)
            for i in self.extNames:
                self.ssh.run(f"sudo -u postgres psql -c \"DROP ROLE {i};\"", pty=True, watchers=[self.sPass])
            self.ssh.run(
                f"sudo -u postgres psql -c \"CREATE ROLE {self.roles[0]} WITH SUPERUSER LOGIN PASSWORD '{self.userDetails['PW']}';\"",
                pty=True, watchers=[self.sPass])
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"INSERT INTO UCreds (role) VALUES ('{self.roles[0]}');\"", pty=True, watchers=[self.sPass])

            print(Colour.MAGENTA + f"Adding the 'postgres' user to the {self.roles[0]} role." + Colour.RESET)
            self.ssh.run(f"sudo -u postgres psql -c \"GRANT {self.roles[0]} TO postgres;\"", pty=True,
                         watchers=[self.sPass])

            print(Colour.MAGENTA + f"Granting universal permissions to the {self.roles[0]} role." + Colour.RESET)
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"GRANT ALL PRIVILEGES ON \"cryReceipt\" TO {self.roles[0]};\"", pty=True,
                         watchers=[self.sPass])
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"GRANT ALL PRIVILEGES ON \"uKeys\" TO {self.roles[0]};\"", pty=True,
                         watchers=[self.sPass])
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"GRANT ALL PRIVILEGES ON \"uCreds\" TO {self.roles[0]};\"", pty=True,
                         watchers=[self.sPass])

            print(Colour.MAGENTA + f"Creating a new {self.roles[1]} role." + Colour.RESET)
            self.ssh.run(f"sudo -u postgres psql -c \"CREATE ROLE {self.roles[1]};\"", pty=True, watchers=[self.sPass])

            print(Colour.MAGENTA + f"Revoking delete privileges from the {self.roles[1]} role." + Colour.RESET)
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"REVOKE DELETE ON \"cryReceipt\" FROM {self.roles[1]};\"", pty=True, watchers=[self.sPass])
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"REVOKE DELETE ON \"uKeys\" FROM {self.roles[1]};\"", pty=True, watchers=[self.sPass])
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"REVOKE DELETE ON \"uCreds\" FROM {self.roles[1]};\"", pty=True, watchers=[self.sPass])

            print(Colour.MAGENTA + f"Altering Receipt table permissions for {self.roles[1]}." + Colour.RESET)
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"GRANT INSERT ON \"cryReceipt\" TO {self.roles[1]};\"", pty=True,
                         watchers=[self.sPass])
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"REVOKE SELECT ON \"cryReceipt\" FROM {self.roles[1]};\"", pty=True,
                         watchers=[self.sPass])

            # Ensure only those in 'User' can input a record, can see only their login details, and can't delete anything.
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"GRANT INSERT ON \"uCreds\" TO {self.roles[1]};\"", pty=True,
                         watchers=[self.sPass])
            self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"REVOKE DELETE ON \"uCreds\" FROM {self.roles[1]};\"", pty=True,
                         watchers=[self.sPass])
            return True
        except Exception as e:
            print(Colour.RED+"An error occurred while altering table permissions."+Colour.RESET)
            print(Colour.RED+str(e)+Colour.RESET)
            return False

    def enableWal(self):
        self.psqlVer = self.ssh.run("psql --version | awk '{print $3}' | cut -d'.' -f1", hide=True,pty=True,watchers=[self.sPass])
        self.psqlVer = self.psqlVer.stdout.strip()
        self.ssh.run(f"sudo sed -i 's/#wal_level = replica/wal_level = logical/g' /etc/postgresql/'{self.psqlVer}'/main/postgresql.conf", pty=True,watchers=[self.sPass])
        print(Colour.GREEN + "WAL logs enabled." + Colour.RESET)
        print(Colour.MAGENTA + "PSQL Service being restarted." + Colour.RESET)
        self.ssh.run("sudo systemctl restart postgresql", pty=True,watchers=[self.sPass])
        print(Colour.GREEN + "PostGreSQL service restarted." + Colour.RESET)
        return True
    def audiTableCheck(self): #Is there a point in this?
        self.tableCheckExec = self.ssh.run("sudo -u postgres psql -d audicrypt -t -c '\dt'", hide=True,pty=True,watchers=[self.sPass])
        if self.tableCheckExec.stdout.strip() == "":
            print(Colour.GREEN + "No AudiCrypt tables found." + Colour.RESET)
            return True
        else:
            print(Colour.RED + "AudiCrypt tables found." + Colour.RESET)
            return False
    def audiTableCreation(self):
        self.userCredQuery = """
        CREATE TABLE IF NOT EXISTS uCreds (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        uName VARCHAR(100) NOT NULL,
        pWord VARCHAR(100) NOT NULL,
        sQ1C VARCHAR(255) NOT NULL,
        sQ1A VARCHAR(255) NOT NULL,
        sQ2C VARCHAR(255) NOT NULL,
        sQ2A VARCHAR(255) NOT NULL
        role VARCHAR(100), 
        );
        """
        self.userKeyQeury = """
        CREATE TABLE IF NOT EXISTS uKeys (
        id SERIAL PRIMARY KEY,
        userCredID INTEGER NOT NULL,
        puKey TEXT NOT NULL,
        prKey TEXT NOT NULL,
        FOREIGN KEY (userCredID) REFERENCES uCreds(id)
        );
        """

        self.cRecQuery = """
        CREATE TABLE IF NOT EXISTS cryReceipt (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        uKeyID INTEGER NOT NULL,
        origHash TEXT NOT NULL,
        newHash TEXT NOT NULL,
        fileName TEXT NOT NULL,
        fileLoc TEXT NOT NULL,
        FOREIGN KEY (uKeyID) REFERENCES uKeys(id)
        );
        -- Grant SELECT privilege to the 'postgres' user
        GRANT SELECT ON cryReceipt TO postgres;
        """
        self.userCredExec = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c '{self.userCredQuery}'", pty=True,watchers=[self.sPass])
        if self.userCredExec.ok:
            print(Colour.GREEN + "User Credentials table created." + Colour.RESET)
            self.userKeyExec = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c '{self.userKeyQeury}'", pty=True,watchers=[self.sPass])
            if self.userKeyExec.ok:
                print(Colour.GREEN + "User Keys table created." + Colour.RESET)
                self.cRecExec = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c '{self.cRecQuery}'", pty=True,watchers=[self.sPass])
                if self.cRecExec.ok:
                    print(Colour.GREEN + "Crypto Receipt table created.\n" + Colour.RESET)
                    return True
                else:
                    print(Colour.RED + "Crypto Receipt table creation failed." + Colour.RESET)
                    self.ssh.close()
                    return False
            else:
                print(Colour.RED + "User Keys table creation failed." + Colour.RESET)
                self.ssh.close()
                return False
        else:
            print(Colour.RED + "User Credentials table creation failed." + Colour.RESET)
            self.ssh.close()
            return False
    def newAudiCryptDatabase(self):
        self.newResult = self.ssh.run("sudo -u postgres psql -c 'CREATE DATABASE audicrypt;'", pty=True,warn=True,watchers=[self.sPass])
        print(self.newResult)
        if self.newResult.ok:
            print(Colour.GREEN + "AudiCrypt database created." + Colour.RESET)
            self.tableCreate = self.audiTableCreation()
            if self.tableCreate == True:
                print(Colour.GREEN + "AudiCrypt tables created." + Colour.RESET)
                self.enableWal()
                print(Colour.GREEN + "AudiCrypt setup complete." + Colour.RESET)
                print(Colour.MAGENTA + "Securely uploading your details to the new database.")
                self.adUpdate = self.adInitTableUpdate()
                if self.adUpdate == True:
                    print(Colour.GREEN + "Admin details uploaded to database." + Colour.RESET)
                    self.ssh.close()
                    print(Colour.MAGENTA+"Perfect! Close to completion now, we just need to alter a few permissions of tables to ensure they can't be maliciously accessed.")
                    self.tabManip = self.adTableManip()
                    if self.tabManip == True:
                        print(Colour.MAGENTA+"AudiCrypt has been completely set up. You will be returned to the main menu. Please log in with your new details.\n"+Colour.RED+"\n\nREMEMBER TO KEEP YOUR PRIVATE KEY SECURE."+Colour.RESET)
                        self.ssh.close()
                        self.checkLog()
                    if self.tabManip == False:
                        print(Colour.RED + "Table manipulation failed." + Colour.RESET)
                        self.ssh.close()
                if self.adUpdate == False:
                    print(Colour.RED + "Admin details upload failed." + Colour.RESET)
                    self.ssh.close()
            else:
                print(Colour.RED + "AudiCrypt tables not created." + Colour.RESET)
        else:
            print(Colour.RED + "AudiCrypt database creation failed." + Colour.RESET)
            self.ssh.close()
    def verifyAudiCryptExists(self): #Does this even bloody work?? Some weird magic here.
        self.existResult = self.ssh.run("sudo -u postgres psql -c \"SELECT datname FROM pg_database WHERE datname='audicrypt';\"", hide=True ,pty=True, watchers=[self.sPass], warn=True)
        if "audicrypt" in self.existResult.stdout:
            return True
        if "audicrypt" not in self.existResult.stdout:
            return False
        if self.existResult.failed:
            return None
    def postGreSQLInstall(self):
        print(self.ssh.run("sudo apt-get install -y postgresql postgresql-contrib", pty=True, watchers=[self.sPass]))
        print(self.ssh.run("sudo systemctl start postgresql", pty=True, watchers=[self.sPass]))
        print(self.ssh.run("sudo systemctl enable postgresql", pty=True, watchers=[self.sPass]))
        return
    def adminSetupDebianSQL(self):
        print(Colour.MAGENTA + "AudiCrypt will now install PostGreSQL on your server." + Colour.RESET)

        from fabric import Connection
        from invoke import Responder
        self.sshVal = {}
        while True:
            while True:
                self.host = input(Colour.MAGENTA + "Enter the IP (IPv4) address of your server: " + Colour.RESET)
                self.reg = rf.regFilters['ipADDRESS']
                if re.match(self.reg, self.host):
                    print(Colour.GREEN + "IP address is valid." + Colour.RESET)
                    self.sshVal['host'] = self.host
                    break
                if not re.match(self.reg, self.host):
                    print(Colour.RED + "Invalid IP address. Please try again." + Colour.RESET)
                    continue
                else:
                    print(Colour.RED + "Invalid value, please try again." + Colour.RESET)

            while True:
                self.port = input(Colour.MAGENTA + "Enter the SSH port of your server: " + Colour.RESET)
                self.reg = rf.regFilters['portSSH']
                if re.match(self.reg, self.port):
                    print(Colour.GREEN + "Port is valid." + Colour.RESET)
                    self.sshVal['port'] = self.port
                    break
                if not re.match(self.reg, self.port):
                    print(Colour.RED + "Invalid port. Please try again." + Colour.RESET)
                    continue
                else:
                    print(Colour.RED + "Invalid value, please try again." + Colour.RESET)

            while True:
                self.user = input(Colour.MAGENTA + "Enter the username of your server: " + Colour.RESET)
                if not self.user:
                    print(Colour.RED + "Username cannot be empty." + Colour.RESET)
                    continue
                print(Colour.GREEN + "Username is valid." + Colour.RESET)
                self.sshVal['user'] = self.user
                break

            while True:
                self.pwd = input(Colour.MAGENTA + "Enter the password of your server: " + Colour.RESET)
                if not self.pwd:
                    print(Colour.RED + "Password cannot be empty." + Colour.RESET)
                    continue
                print(Colour.GREEN + "Password is valid." + Colour.RESET)
                self.sshVal['pass'] = self.pwd
                break
            break

        self.ssh = Connection(self.sshVal['host'], user=self.sshVal['user'], port=self.sshVal['port'], connect_kwargs={"password": self.sshVal['pass']})
        self.sPass = Responder(pattern=r'\[sudo\] password for '+self.sshVal['user']+':', response=f'{self.sshVal["pass"]}\n')
        print(self.ssh.run("sudo apt-get update", pty=True,watchers=[self.sPass]))
        self.psCheck = self.ssh.run("dpkg -l | grep postgresql", pty=True,watchers=[self.sPass],warn=True)
        if self.psCheck.ok:
            print(Colour.GREEN + "PostGreSQL already installed." + Colour.RESET)
            self.psqlCheck = self.ssh.run("systemctl is-active postgresql",pty=True,warn=True)
            if self.psqlCheck.stdout.strip() == 'active':
                print(Colour.GREEN + "PostGreSQL already running." + Colour.RESET)
            else:
                print(Colour.RED + "PostGreSQL not running, beginning execution." + Colour.RESET)
                print(self.ssh.run("sudo systemctl start postgresql", pty=True, watchers=[self.sPass]))
                print(self.ssh.run("sudo systemctl enable postgresql", pty=True, watchers=[self.sPass]))
        else:
            self.postGreSQLInstall()
        print(Colour.GREEN + "PostGreSQL installed." + Colour.RESET)
        time.sleep(Constants.SLEEPTIME)
        print(Colour.MAGENTA + "You now need to edit a setting for AudiCrypt to continue." + Colour.RESET)
        time.sleep(Constants.SLEEPTIME)
        print(Colour.MAGENTA + "Please open the file "+Colour.RESET+"'postgresql.conf with your preferred text editor (i.e. nano, vim, etc.)")
        time.sleep(Constants.SLEEPTIME)
        print(Colour.MAGENTA + "It can typically be found in '/etc/postgresql/16/main/postgresql.conf.'"+Colour.RESET)
        time.sleep(Constants.SLEEPTIME)
        print(Colour.MAGENTA + "Once you're here, edit the line 'listen_addresses' '*', \n\nThen, edit 'pg_hba.conf' from 'localhost' to your public IP Address, with a /32 bitmask."+ Colour.RESET)
        while True:
            self.confEdit = input(Colour.MAGENTA + "Have you completed this step? [y/n]" + Colour.RESET)
            if self.confEdit.lower() == "y" or self.confEdit.lower() == "yes":
                print(Colour.GREEN + "Configuration complete." + Colour.RESET)
                break
            if self.confEdit.lower() == "n" or self.confEdit.lower() == "no":
                print(Colour.RED + "Please complete the configuration before continuing." + Colour.RESET)
                continue
            else:
                print(Colour.RED + "Invalid response. Please try again." + Colour.RESET)
        print(Colour.MAGENTA + "AudiCrypt will now SSH into your server to complete the configuration, standby for more updates." + Colour.RESET)
        self.ssh.run("sudo systemctl restart postgresql", pty=True,watchers=[self.sPass])
        self.aAdminStatus = self.ssh.run("sudo -u postgres psql -d audicrypt -c \"SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = 'audiadmin';\"", hide=True, pty=True, watchers=[self.sPass])
        if "audiadmin" in self.aAdminStatus.stdout:
            print(Colour.RED + "An Admin role for an AudiCrypt configuration already exists, please log in to this account to modify AudiCrypt." + Colour.RESET)
            self.ssh.close()
            self.checkLog()
        else:
            print(Colour.GREEN + "No AudiCrypt Admin role found." + Colour.RESET)
            self.verifyResult = self.verifyAudiCryptExists()
            if self.verifyResult == True:
                print(Colour.GREEN + "AudiCrypt database exists." + Colour.RESET)
                while True:
                    self.datCheck = input(
                        Colour.RED + "An AudiCrypt database already exists, to progress further - it must be wiped. Enter [Yes, Y] to proceed." + Colour.RESET)
                    if self.datCheck.lower() == "yes" or self.datCheck.lower() == "y":
                        self.ssh.run("sudo -u postgres psql -c 'DROP DATABASE audicrypt;'", pty=True,
                                     watchers=[self.sPass])
                        print(Colour.GREEN + "Database wiped." + Colour.RESET)
                        break
                    else:
                        print(Colour.RED + "Invalid response. Please try again." + Colour.RESET)
                        continue
                self.newAudiCryptDatabase()
            if self.verifyResult is None:
                print(Colour.RED + "An error occurred while checking the AudiCrypt database." + Colour.RESET)
                self.ssh.close()
            if self.verifyResult == False:
                print(Colour.RED + "AudiCrypt database does not exist." + Colour.RESET)
                self.newAudiCryptDatabase()
    def adminSetupDebianSSH(self):
        print(Colour.MAGENTA + """
        To install SSH on your Debian/Ubuntu system, please run the following commands:
        #To update the package list 
        sudo apt-get update
        
        #To install the SSH server
        sudo apt-get install openssh-server
        
        #To start the SSH service
        sudo service ssh start
        """ + Colour.RESET)
        while True:
            self.autoStart = input(Colour.MAGENTA + "Do you want SSH to start automatically on boot? [y/n]" + Colour.RESET)
            if self.autoStart.lower() == "y" or self.autoStart.lower() == "yes":
                print(Colour.GREEN + "To start SSH automatically on boot:" + Colour.RESET)
                print(Colour.MAGENTA + """
                sudo update-rc.d ssh defaults
                """ + Colour.RESET)
                print("")
                break
            if self.autoStart.lower() == "n" or self.autoStart.lower() == "no":
                print(Colour.RED + "SSH will not start automatically on boot." + Colour.GREEN + " Setup complete." + Colour.RESET)
                break
            else:
                print(Colour.RED + "Invalid response." + Colour.RESET)
        while True:
            self.sshOkay = input(Colour.MAGENTA + "Is SSH working correctly? [y/n]" + Colour.RESET)
            if self.sshOkay.lower() == "y" or self.sshOkay.lower() == "yes":
                print(Colour.GREEN + "Fantastic! Let's get this service configured." + Colour.RESET)
                break
            if self.sshOkay.lower() == "n" or self.sshOkay.lower() == "no":
                print(Colour.RED + "Please ensure SSH is working correctly before continuing." + Colour.RESET)
                continue
            else:
                print(Colour.RED + "Invalid response." + Colour.RESET)
        print(Colour.MAGENTA + "AudiCrypt will now SSH into your server to complete the configuration, standby for more updates." + Colour.RESET)
        self.adminSetupDebianSQL()

    def clientSetup(self):
        from fabric import Connection
        from invoke import Responder
        import socket
        print(Colour.GREEN + "Client setup proceeding." + Colour.RESET)
        print(Colour.GREEN + """
        As a client of your local AudiCrypt network,
        we require you to provide a few details of your
        server. If you haven't done this before, don't
        worry.
        """ + Colour.RESET + Colour.MAGENTA + """
        - As your Admin has already configured an instance
        of AudiCrypt, you will need to provide a few details 
        of yourself.
        
        - This will be used to make an account on your local
        AudiCrypt instance. The app will then continue in the background.
        
        - An Admin will provide a directory for you. Everyone in the network
        will work within this directory. All changes you make will be 
        cryptographically signed, and logged securely.
        
        - This is to maintain enterprise-level security, data policy,
        and non-repudiation. 
        """ + Colour.RESET)
        self.getDatChack = False
        while True:
            self.getData = input(Colour.MAGENTA+"Do you agree to share your data with AudiCrypt for this purpose? [y/n] or [Yes/No]"+Colour.RESET)
            if self.getData.lower() == 'y' or self.getData.lower() == 'yes':
                print(Colour.GREEN+"You have agreed to share your data."+Colour.RESET)
                self.getDatChack = True
                break
            if self.getData.lower() == 'n' or self.getData.lower() == 'no':
                print(Colour.RED+"You must agree to share your data to continue."+Colour.RESET)
                self.getDatChack = False
                break
            else:
                print(Colour.RED+'Invalid response.'+Colour.RESET)
                continue
        if self.getDatChack == True:
            self.sshVal = {}
            while True:
                self.getAdmin = input(Colour.MAGENTA + "Setup will only progress with Admin here. Type [y/yes] to continue." + Colour.RESET)
                if self.getAdmin.lower() == 'y' or self.getAdmin.lower() == 'yes':
                    print(Colour.GREEN + "Admin setup proceeding." + Colour.RESET)
                    while True:
                        self.host = input(Colour.MAGENTA + "Enter the IP (IPv4) address of your server: " + Colour.RESET)
                        self.reg = rf.regFilters['ipADDRESS']
                        if re.match(self.reg, self.host):
                            print(Colour.GREEN + "IP address is valid." + Colour.RESET)
                            self.sshVal['host'] = self.host
                            break
                            #The code below DOES work I believe, but as I tested with a virtual machine - it was not necessary.
                            #This will be used in distribution though.

                            #while True:
                            #    try:
                            #        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            #        self.socket.connect(('8.8.8.8', 80))  # Google DNS
                            #        self.IP = self.socket.getsockname()[0]
                            #        print(self.IP)
                            #    except Exception as e:
                            #        print(Colour.RED + f"An error occurred while checking your IP address: {e}" + Colour.RESET)
                            #        self.IP = None
                            #    finally:
                            #        self.socket.close()
                            #        break
                            #if self.IP != None:
                            #    self.ipNet = ipaddress.ip_network(self.IP, strict=False)
                            #    if ipaddress.ip_address(self.host) in self.ipNet:
                            #        print(Colour.GREEN + "IP address is valid." + Colour.RESET)
                            #        break
                            #    else:
                            #        print(Colour.RED + "IP address is not in your network. Please try again." + Colour.RESET)
                            #        continue
                            #else:
                            #    print(Colour.RED + "An error occurred while checking your IP address. Check your internet connection." + Colour.RESET)
                            #    continue

                        if not re.match(self.reg, self.host):
                            print(Colour.RED + "Invalid IP address. Please try again." + Colour.RESET)
                            continue
                        else:
                            print(Colour.RED + "Invalid value, please try again." + Colour.RESET)
                    while True:
                        self.port = input(Colour.MAGENTA + "Enter the SSH port of your server: " + Colour.RESET)
                        self.reg = rf.regFilters['portSSH']
                        if re.match(self.reg, self.port):
                            print(Colour.GREEN + "Port is valid." + Colour.RESET)
                            self.sshVal['port'] = self.port
                            self.failSafe = False
                            while self.failSafe == False:
                                if self.port != 22:
                                    while True:
                                        self.portChange = input(
                                            Colour.MAGENTA + "Would you like to change the default SSH port? [y/n]" + Colour.RESET)
                                        if self.portChange.lower() == 'y' or self.portChange.lower() == 'yes':
                                            print(Colour.GREEN + "Changing SSH port." + Colour.RESET)
                                            self.failSafe = True
                                            break
                                        if self.portChange.lower() == 'n' or self.portChange.lower() == 'no':
                                            print(Colour.RED + "Using default SSH port." + Colour.RESET)
                                            self.port = 22
                                            self.sshVal['port'] = self.port
                                            self.failSafe = True
                                            break
                                        else:
                                            print(Colour.RED + "Invalid response." + Colour.RESET)
                                            continue
                                else:
                                    print(Colour.GREEN + f"Port {self.port} is valid." + Colour.RESET)
                                    self.failSafe = True
                            break
                        if not re.match(self.reg, self.port):
                            print(Colour.RED + "Invalid port. Please try again." + Colour.RESET)
                            continue
                        else:
                            print(Colour.RED + "Invalid value, please try again." + Colour.RESET)
                    while True:
                        self.user = input(Colour.MAGENTA + "Enter the username of your server: " + Colour.RESET)
                        if not self.user:
                            print(Colour.RED + "Username cannot be empty." + Colour.RESET)
                            continue
                        if isinstance(self.user, str) == False:
                            print(Colour.RED + "Username must be a string." + Colour.RESET)
                            continue
                        else:
                            print(Colour.GREEN + "Username is valid." + Colour.RESET)
                            self.sshVal['user'] = self.user
                            break
                    while True:
                        self.pwd = input(Colour.MAGENTA + "Enter the password of your server: " + Colour.RESET)
                        if not self.pwd:
                            print(Colour.RED + "Password cannot be empty." + Colour.RESET)
                            continue
                        if isinstance(self.pwd, str) == False:
                            print(Colour.RED + "Password must be a string." + Colour.RESET)
                            continue
                        else:
                            print(Colour.GREEN + "Password is valid." + Colour.RESET)
                            self.sshVal['pass'] = self.pwd
                            break
                    break
                if self.getAdmin.lower() == 'n' or self.getAdmin.lower() == 'no':
                    print(Colour.RED + "Admin setup required." + Colour.RESET)
                    continue
                else:
                    print(Colour.RED + "Invalid response." + Colour.RESET)
                    continue
        else:
            print(Colour.RED+"Client setup failed, returning to menu."+Colour.RESET)
            self.checkLog()
        self.ssh = Connection(self.sshVal['host'], user=self.sshVal['user'], port=self.sshVal['port'], connect_kwargs={"password": self.sshVal['pass']})
        self.sPass = Responder(pattern=r'\[sudo\] password for '+self.sshVal['user']+':', response=f'{self.sshVal["pass"]}\n')
        self.newUserStatus = False
        self.newUserNumber = [i for i in range(1, 1000)]
        self.loopCount = 1
        while self.newUserStatus == False:
            self.getUserValue = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = 'audiuser{self.loopCount}';\"", hide=True,pty=True, watchers=[self.sPass])
            if f'audiuser{self.loopCount}' in self.getUserValue.stdout.strip():
                self.loopCount += 1
                self.newUserStatus = False
            if f'audiuser{self.loopCount}' not in self.getUserValue.stdout.strip():
                self.newUserStatus = True
        #Command to check whether details already exist on database or not.
        self.usNameCheck = self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"SELECT uName FROM uCreds WHERE uName='{self.userDetails['UN']}';\"", warn=True,pty=True, watchers=[self.sPass])
        if self.usNameCheck.ok:
            if self.userDetails['UN'] not in self.usNameCheck.stdout.strip():
                print(Colour.GREEN + "User details not found." + Colour.RESET)
                # New command to SSH into psql audicrypt, make a new user with this 'audiuser(i)' name, and give it priivleges of 'audiuser'.
                print(Colour.MAGENTA + f"Creating a new user." + Colour.RESET)
                self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"CREATE USER audiuser{self.loopCount} WITH PASSWORD '{self.userDetails['PW']}';\"", pty=True, watchers=[self.sPass])
                self.ssh.run(f"sudo -u postgres psql -d audicrypt -c \"GRANT audiuser TO audiuser{self.loopCount};\"", pty=True, watchers=[self.sPass])

                # Input these details into all relevant tables.
                print(Colour.GREEN + "Successful Login! "+Colour.MAGENTA +"Inserting user details into the database." + Colour.RESET)
                self.uCredInsert = self.ssh.run("sudo -u postgres psql -d audicrypt -c \"INSERT INTO uCreds (name,uName,pWord,sQ1C,sQ1A,sQ2C,sQ2A) VALUES ('"+self.userDetails['FN']+"','"+self.userDetails['UN']+"','"+self.userDetails['PW']+"','"+self.userDetails['SQ1C']+"','"+self.userDetails['SQ1A']+"','"+self.userDetails['SQ2C']+"','"+self.userDetails['SQ2A']+"', '"+f'audiuser{self.loopCount}'+"');\"", pty=True, watchers=[self.sPass])
                if self.uCredInsert.ok:
                    time.sleep(Constants.SLEEPTIME)
                    print(Colour.GREEN + "User details into the database." + Colour.RESET)
                    self.puKeyStripped = self.puKey.replace("----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
                    self.puKeyStripped = self.puKeyStripped.replace("----END PUBLIC KEY-----", "")
                    self.puKeyStripped = str(self.puKeyStripped.strip())
                    self.prKeyStripped = str(self.prKey)
                    self.prKeyStripped = (self.prKeyStripped.split("-----BEGIN RSA PRIVATE KEY-----")[1]).split("-----END RSA PRIVATE KEY-----")
                    self.prKeyStripped = self.prKeyStripped[0].strip()
                    print(Colour.RED+ '\n\nPLEASE MEMORISE/KEEP A NOTE OF YOUR PRIVATE KEY. THIS IS REQUIRED FOR LOGIN.'+Colour.RESET)
                    time.sleep(Constants.SLEEPTIME+3)
                    print(Colour.MAGENTA + self.prKeyStripped + '\n' + Colour.RESET)
                    self.prKeyStripEnc = self.hashString(self.prKeyStripped)
                    print(Colour.GREEN+"Uploading Keys to Database."+Colour.RESET)

                    self.puKeyUpload = self.ssh.run("sudo -u postgres psql -d audicrypt -c \"INSERT INTO uKeys (userCredID,puKey,prKey) VALUES ((SELECT id FROM uCreds WHERE uName='"+self.userDetails['UN']+"'),'"+self.puKeyStripped+"','"+self.prKeyStripEnc+"');\"", pty=True, watchers=[self.sPass])
                    if self.puKeyUpload.ok:
                        print(Colour.GREEN + "Keys uploaded to database." + Colour.RESET)
                        time.sleep(Constants.SLEEPTIME)
                        print(Colour.GREEN + "User setup complete." + Colour.RESET)
                        print(Colour.MAGENTA + "You will be returned to the main menu. Please login with your new details." + Colour.RESET)
                        self.ssh.close()
                        self.checkLog()
            else:
                print(Colour.RED + "User details found, please login with them." + Colour.RESET)
                self.checkLog()
        else:
            print(Colour.RED + "An error occurred while checking the database, returning to main menu." + Colour.RESET)
            self.ssh.close()
            self.checkLog()



    def adminSetup(self):
        print(Colour.GREEN + "Admin setup proceeding." + Colour.RESET)
        print(Colour.GREEN + """
        As the Admin of your local AudiCrypt network,
        we require you to provide a few details of your
        server. If you haven't done this before, don't
        worry.
        
        """ + Colour.RESET + Colour.MAGENTA +"""
        - This will create a new PostGreSQL database on your
        server. If you don't have this it will be installed.
        Make sure you have a working internet connection.
        
        - SSH will be installed, and configured, on your server.
        By default, the port is 22. If you'd like to use a different
        port, please specify - the configuration will be modified accordingly.
        
        - AudiCrypt will create a few tables. These will store user credentials,
        and a few more important details. WAL logs will also be created, and encrypted,
        with your details by default.
        
        - SSH will also be modified on your system to restrict access, and only allow
        certain operations to commence. This is to protect your data from any malicious attacks,
        and ensure the integrity of your AudiCrypt confiiguration is not compromised.
        """ + Colour.RESET)
        while True:
            self.adYes = input(Colour.GREEN + "Do you want to proceed with the setup? [y/yes/Yes/YES]" + Colour.RESET)
            if self.adYes.lower() == "y" or self.adYes.lower() == "yes":
                print(Colour.GREEN + "Proceeding with setup." + Colour.RESET)
                break
            else:
                print(Colour.RED + "Invalid response." + Colour.RESET)
        print(Colour.GREEN + "Fantastic, let's get started." + Colour.RESET)
        print(Colour.MAGENTA + "Unfortunately, AudiCrypt can't install SSH on your machine directly. You must do it yourself." + Colour.RESET)
        while True:
            self.systemChoice = input(Colour.MAGENTA + "Enter the system your server is using (Linux/Windows): " + Colour.RESET)
            self.__debLinux = ['ubuntu','debian']
            self.__rhLinux = ['fedora','redhat','red hat','rhel','centos']
            if self.systemChoice.lower() == "linux" or self.systemChoice.lower() == "l" or self.systemChoice.lower() == "lin":
                while True:
                    self.linChoice = input(Colour.MAGENTA + "Enter the distribution of Linux your server is using (Ubuntu/Debian/Fedora/RedHat/CentOS): " + Colour.RESET)
                    if self.linChoice.lower() in self.__debLinux:
                        print(Colour.GREEN + "Debian/Ubuntu detected." + Colour.RESET)
                        self.linChoice = True
                        break
                    if self.linChoice.lower() in self.__rhLinux:
                        print(Colour.GREEN + "RedHat/CentOS/Fedora detected." + Colour.RESET)
                        self.linChoice = False
                        break
                    else:
                        print(Colour.RED + "Invalid distribution. Please try again." + Colour.RESET)
                if self.linChoice == True or self.linChoice == False:
                    break
            if self.systemChoice.lower() == "windows" or self.systemChoice.lower() == "win" or self.systemChoice.lower() == "w":
                continue
        if self.linChoice == True:
            self.adminSetupDebianSSH()
        if self.linChoice == False:
            print(Colour.RED + "RedHat/CentOS/Fedora setup is not yet supported." + Colour.RESET)

    def printSec(self):
        self.securityQuestions = sq.securityList()
        for key, question in self.securityQuestions.items():
            print(Colour.MAGENTA + key + ". " + question + Colour.RESET)
        return

    def keyGenRSA(self):
        from Crypto.PublicKey import RSA
        self.key = RSA.generate(2048)
        self.combKey = "".join([str(value) for value in self.userDetails.values()])
        self.puKey = self.key.publickey().export_key().decode()
        self.prKey = self.key.export_key().decode(),

    def newUser(self):
        while True:
            self.rs = input(Colour.MAGENTA + "Enter a role (Admin/Client): " + Colour.RESET)
            if self.rs.lower() == "admin" or self.rs.lower() == "a":
                print(Colour.GREEN + "Admin role selected." + Colour.RESET)
                break
            if self.rs.lower() == "client" or self.rs.lower() == "c":
                print(Colour.GREEN + "Client role selected." + Colour.RESET)
                break
            else:
                print(Colour.RED + "Invalid role. Please try again." + Colour.RESET)
        self.userDetails = {}
        while True:
            self.userName = input(Colour.MAGENTA + "Enter a username: " + Colour.RESET)
            self.reg = rf.regFilters['username']
            if isinstance(self.userName, str) == False:
                print(Colour.RED + "Username must be a String." + Colour.RESET)
                continue
            if not self.userName:
                print(Colour.RED + "Username cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.userName):
                print(Colour.RED + "Username must contain at least 1 lowercase, 1 uppercase, 1 digit, 1 special character, and be 8 characters long." + Colour.RESET)
                continue
            print(Colour.GREEN + "Username is valid." + Colour.RESET)
            self.userDetails['UN'] = self.hashString(self.userName)
            break

        while True:
            self.passWord = input(Colour.MAGENTA + "Enter a password: " + Colour.RESET)
            self.reg = rf.regFilters['password']
            if isinstance(self.passWord, str) == False:
                print(Colour.RED + "Password must be a String." + Colour.RESET)
                continue
            if not self.passWord:
                print(Colour.RED + "Password cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.passWord):
                print(Colour.RED + "Password must contain at least 1 lowercase, 2 uppercase, 2 special characters, and be 12-20 characters long." + Colour.RESET)
                continue
            print(Colour.GREEN + "Password is valid." + Colour.RESET)
            self.userDetails['PW'] = self.hashString(self.passWord)
            break

        self.printSec()

        while True:
            self.securityQuestionNumber = input(Colour.MAGENTA + "Enter a security question number: " + Colour.RESET)
            if self.securityQuestionNumber not in sq.securityList():
                print(Colour.RED + "Invalid security question number." + Colour.RESET)
                continue
            print(Colour.GREEN + "Security question is valid." + Colour.RESET)
            self.userDetails['SQ1C'] = self.hashString(sq.securityList()[self.securityQuestionNumber])
            break

        while True:
            self.secQuestionAnswer = input(Colour.MAGENTA + "Enter a security question answer: " + Colour.RESET)
            self.reg = rf.regFilters['security']
            if isinstance(self.secQuestionAnswer, str) == False:
                print(Colour.RED + "Security question must be a String." + Colour.RESET)
                continue
            if not self.secQuestionAnswer:
                print(Colour.RED + "Security question cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.secQuestionAnswer):
                print(Colour.RED + "Security question must contain at least 1 uppercase letter, and be at least 5 characters long." + Colour.RESET)
                continue
            print(Colour.GREEN + "Security question is valid." + Colour.RESET)
            self.userDetails['SQ1A'] = self.hashString(self.secQuestionAnswer)
            break

        self.printSec()

        while True:
            self.securityQuestionNumber = input(Colour.MAGENTA + "Enter a security question number: " + Colour.RESET)
            if self.securityQuestionNumber not in sq.securityList():
                print(Colour.RED + "Invalid security question number." + Colour.RESET)
                continue
            print(Colour.GREEN + "Security question is valid." + Colour.RESET)
            self.userDetails['SQ2C'] = self.hashString(sq.securityList()[self.securityQuestionNumber])
            break

        while True:
            self.secQuestionAnswer = input(Colour.MAGENTA + "Enter a security question answer: " + Colour.RESET)
            self.reg = rf.regFilters['security']
            if isinstance(self.secQuestionAnswer, str) == False:
                print(Colour.RED + "Security question must be a String." + Colour.RESET)
                continue
            if not self.secQuestionAnswer:
                print(Colour.RED + "Security question cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.secQuestionAnswer):
                print(Colour.RED + "Security question must contain at least 1 uppercase letter, and be at least 5 characters long." + Colour.RESET)
                continue
            print(Colour.GREEN + "Security question is valid." + Colour.RESET)
            self.userDetails['SQ2A'] = self.hashString(self.secQuestionAnswer)
            break

        while True:
            self.fullName = input(Colour.MAGENTA + "Enter your full name: " + Colour.RESET)
            self.reg = rf.regFilters['fullName']
            if isinstance(self.fullName, str) == False:
                print(Colour.RED + "Full Name must be a String." + Colour.RESET)
                continue
            if not self.fullName:
                print(Colour.RED + "Full Name cannot be empty." + Colour.RESET)
                continue
            if not re.match(self.reg, self.fullName):
                print(Colour.RED + "Full Name must contain only letters and be in the format: First Last" + Colour.RESET)
                continue
            print(Colour.GREEN + "Full Name is valid." + Colour.RESET)
            self.userDetails['FN'] = self.hashString(self.fullName)
            break
        print(Colour.GREEN + "Account creation successful." + Colour.RESET)
        self.keyGenRSA()
        if self.rs.lower() == "admin" or self.rs.lower() == "a":
            self.adminSetup()
        if self.rs.lower() == "client" or self.rs.lower() == "c":
            self.clientSetup()

    def checkLog(self):
        while True:
            self.accountResponse = (str(input((Colour.MAGENTA + "Do you already have an account with your local AudiCrypt (Admin/Client)? [y/n] or [Yes/No]" + Colour.RESET))))
            if self.accountResponse.lower() == "y" or self.accountResponse.lower() == "yes":
                print(Colour.GREEN + "Welcome back! Proceeding to login." + Colour.RESET)
                self.curUser()
                break
            if self.accountResponse.lower() == "n" or self.accountResponse.lower() == "no":
                print(Colour.GREEN + "Creating a new account." + Colour.RESET)
                self.newUser()
                break
            else:
                print(Colour.RED + "Invalid response. Please try again." + Colour.RESET)
    def __init__(self):
        signal.signal(signal.SIGINT, self.signalHandler)
        signal.signal(signal.SIGTERM, self.signalHandler)
        self.pyVersion = ".".join(map(str, sys.version_info[:2]))
        self.majVersion = int(self.pyVersion.split(".")[0])
        if (self.majVersion < 3):
            print(Colour.RED + "Please use Python 3.x." + Colour.RESET)
            globals().clear()
            sys.exit(1)
        else:
            print(Colour.GREEN + "Python 3.x detected." + Colour.RESET)
            self.checkAV()
            self.checkDependencies()
            self.checkLog()
if __name__ == "__main__":
    cnst = Constants()
    pc = UserUI()
else:
    print(Colour.RED + "This script must be run as the main module." + Colour.RESET)
    globals().clear()
    sys.exit(1)