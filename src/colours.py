class Colour():
    MAGENTA = "\033[35m" # Magenta
    RESET = "\033[0m" # Reset
    RED = "\033[31m" # Red
    GREEN = "\033[32m" # Green


if __name__ == '__main__':
    print(Colour.RED+"This .py file can only be executed as a module, access denied."+Colour.RESET)