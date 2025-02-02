class RegexFilters():
    regFilters = {
        'username': r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
        'password': r'^(?=.*[a-z])(?=.*[A-Z]{2,})(?=.*[@$!%*?&]{2,}).{12,20}$',
        'security': r'^(?=.*[a-z])(?=.*[A-Z]).{5,}$',
        'fullName': r'^[A-Z][a-z]*\s[A-Z][a-z]*$',
        'ipADDRESS': r'^(?:(?:25[0-5,}]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
        'portSSH': r'^(22|[1-9][0-9]{2,3}|[1-5][0-9]{3,4}|6[0-5][0-9]{3}|65[0-4][0-9]{2}|6553[0-5])$',
    }

if __name__ == '__main__':
    print(Colour.RED+"This .py file can only be executed as a module, access denied."+Colour.RESET)