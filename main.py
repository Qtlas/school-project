from traitements import *
from utils import *


if __name__ == "__main__":
    print_welcome()
    choice = ''
    while choice != 'exit':
        choice = input("SEARCH BY : ")
        if choice == "all":
            data = 