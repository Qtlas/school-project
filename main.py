import json
import os


def json_to_dict(filename : str) -> dict:
    with open(filename, 'r') as f:
        data = f.read()
        json_data = json.loads(data)
        return json_data


def load_json_by_range_year(yearA : int, yearB : int) -> dict:
    if yearA < 1999 or yearB > 2026: return -1
    
    json_data = dict()

    for year in range(yearA, yearB+1):
        for json_cve in os.listdir(f"db/{year}/"):
            json_data[str(year)] = dict()
            json_data[str(year)][json_cve] = json_to_dict(f"db/{year}/{json_cve}")
    
    return json_data



print(load_json_by_range_year(2024, 2026)['2024'])

    