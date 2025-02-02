import clamd
from colours import Colour
class clamdScan():
    def __init__(self):
        self.cd = clamd.ClamdUnixSocket()
    def scan(self, file):
        self.file = file
        try:
            self.result = self.cd.scan(self.file)
            if self.result(self.file[0] == 'OK'):
                return True
            else:
                return False
        except Exception as e:
            return str(e)

if __name__ == '__main__':
    print(Colour.RED+"This .py file can only be executed as a module, access denied."+Colour.RESET)