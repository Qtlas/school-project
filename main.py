import json
import os
import math
import matplotlib.pyplot as plt

SEARCH_DICT = {"CWE" : "nvd,weaknesses", "DATE" : "nvd,created", "CVSS" : "nvd,metrics,cvssV3_1,score", "TITLE" : "advisories,title"}

def json_to_dict(filename : str) -> dict:
    with open(filename, 'r') as f:
        data = f.read()
        json_data = json.loads(data)
        return json_data


def load_json_by_range_year(yearA : int, yearB : int) -> dict:
    if yearA < 1999 or yearB > 2026: return -1
    
    json_data = dict()

    for year in range(yearA, yearB+1):
        json_data[str(year)] = dict()
        for json_cve in os.listdir(f"db/{year}/"):
            json_data[str(year)][json_cve.split('.')[0]] = json_to_dict(f"db/{year}/{json_cve}")
    
    return json_data

def get_by_str_path(obj_dict : dict, str_path : str):
    path = str_path.split(',')
    val = obj_dict[path[0]]
    for key in path[1:]:
        val = val[key]
    return val


def search_by(obj_dict : dict, key : str):
    if key not in SEARCH_DICT: return -1
    return get_by_str_path(obj_dict, SEARCH_DICT[key])


