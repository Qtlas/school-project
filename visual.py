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



def cwe_repartition(yearA : int, yearB : int, top_n  : int = 10):
    data = load_json_by_range_year(yearA, yearB)
    f = {}
    for year in range(yearA, yearB+1):
        for cve in data[str(year)]:
            for cwe in search_by(data[str(year)][cve], "CWE"):
                if cwe in f:
                    f[cwe] += 1
                else:
                    f[cwe] = 1
 
    sorted_items = sorted(f.items(), key=lambda x: x[1], reverse=True)

    labels = []
    sizes = []
    others = 0

    for i, (cwe, count) in enumerate(sorted_items):
        if i < top_n:
            labels.append(cwe)
            sizes.append(count)
        else:
            others += count

    if others > 0:
        labels.append("OTHER")
        sizes.append(others)

    plt.figure()
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=100)
    plt.title(f"CWE repartition ({yearA}–{yearB})")
    plt.axis('equal')
    plt.show()
    

nb_cve_per_year(2024, 2026)
cwe_repartition(2024, 2026)