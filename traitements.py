import matplotlib.pyplot as plt
from utils import *

def nb_cve_per_year(data : dict):
    f = {k : len(data[k]) for k in data}

    plt.figure()
    plt.plot(f.keys(), f.values(), marker='o')
    plt.xlabel("Year")
    plt.ylabel("Number of CVEs")
    plt.title("Number of CVEs per Year")
    plt.grid(True)
    plt.show()



def cwe_repartition(data : dict, top_n  : int = 10):
    f = {}
    for year in data:
        for cve in data[str(year)]:
            for cwe in data[str(year)][cve]["CWE"]:
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


def cvss_score_distrib(data: dict):
    scores = []
    for year in data:
        for cve in data[str(year)]:
            score = data[str(year)][cve].get("SCORE")
            if score and score != '':
                scores.append(float(score))
    
    plt.figure(figsize=(12, 6))
    plt.hist(scores, bins=20, edgecolor='black', alpha=0.7)
    plt.xlabel("CVSS Score")
    plt.ylabel("Number of CVEs")
    plt.title("Score CVSS Distribution")
    plt.grid(True, alpha=0.3)
    

    plt.axvline(x=4.0, color='yellow', linestyle='--', label='Medium (4.0)')
    plt.axvline(x=7.0, color='orange', linestyle='--', label='High (7.0)')
    plt.axvline(x=9.0, color='red', linestyle='--', label='Critical (9.0)')
    plt.legend()
    plt.tight_layout()
    plt.show()


def month_distrib(data: dict):
    months = {i: 0 for i in range(1, 13)}
    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
    dates = [data[year][cve].get("DATE") for year in data for cve in data[year] 
             if data[year][cve].get("DATE")]
    
    for date_str in dates:
        month = int(date_str.split('-')[1])
        months[month] += 1
    
    plt.figure(figsize=(12, 6))
    plt.bar(month_names, [months[i] for i in range(1, 13)], color='skyblue', edgecolor='black')
    plt.xlabel("Month")
    plt.ylabel("Number of CVEs")
    plt.title("Distribution des CVE dans l'annees")
    plt.grid(True, alpha=0.3, axis='y')
    plt.tight_layout()
    plt.show()
