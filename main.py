from traitements import *
from utils import *


if __name__ == "__main__":
    #print_welcome()
    choice = ''
    while choice != 'exit':
        choice = "all"
        if choice == "all":
            data = load_json_by_range_year(None)
        else:
            logicTab = expression_to_tab(choice)
            data = load_json_by_range_year(logicTab)
        
        if data is None:
            exit("error")

        produit_most_vuln(data, 5)
        break
        