import json
import os
import math
import matplotlib.pyplot as plt

SEARCH_DICT = {"CVE" : ["cve"], "CWE" : ["nvd,weaknesses"], "DATE" : ["nvd,created"], "CVSS" : ["nvd,metrics,cvssV2_0,score","nvd,metrics,cvssV3_1,score"], "METRIC" : ["nvd,metrics,cvssV2_0,vector","nvd,metrics,cvssV3_1,vector"], "TITLE" : ["advisories,title", "mitre,title"], "DESC" : ["nvd,description"], "VENDOR" : ["nvd,vendors"]}

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
        for json_cve in os.listdir(f"opencve-kb/{year}/"):
            json_data[str(year)][json_cve.split('.')[0]] = json_to_dict(f"opencve-kb/{year}/{json_cve}")
    
    return json_data

def get_by_str_path(obj_dict : dict, path_list : list):
    val = ""
    for str_path in path_list:
        path = str_path.split(',')
        try:
            val = obj_dict[path[0]]
            for key in path[1:]:
                
                    val = val[key]
        except:
            pass
    return val


def search_by(obj_dict : dict, key : str):
    if key not in SEARCH_DICT: return -1
    return get_by_str_path(obj_dict, SEARCH_DICT[key])


