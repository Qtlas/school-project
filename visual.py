from main import *


def nb_cve_per_year(yearA : int, yearB : int):
    data = load_json_by_range_year(yearA, yearB)
    f = {k : len(data[k]) for k in data}

    plt.figure()
    plt.plot(f.keys(), f.values(), marker='o')
    plt.xlabel("Year")
    plt.ylabel("Number of CVEs")
    plt.title("Number of CVEs per Year")
    plt.grid(True)
    plt.show()



def nb_cve_per_year(yearA : int, yearB : int):
    data = load_json_by_range_year(yearA, yearB)
