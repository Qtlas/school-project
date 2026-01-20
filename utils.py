import json
import os
import math



def json_to_dict(filename : str) -> dict:
    with open(filename, 'r') as f:
        data = f.read()
        json_data = json.loads(data)
        return json_data


def load_json_by_range_year(logicExpression : str) -> dict:
    if yearA < 2015 or yearB > 2026: return -1
    
    json_data = dict()

    for year in range(yearA, yearB+1):
        json_data[str(year)] = dict()
        for json_cve in os.listdir(f"db/{year}/"):
            temp_data = json_to_dict(f"db/{year}/{json_cve}")
            if logicExpression is None or is_valid_cve_by_logic_tab(temp_data, expression_to_tab(logicExpression)):
                json_data[str(year)][json_cve.split('.')[0]] = temp_data
    
    return json_data

def expression_to_tab(logicExpression : str) -> list:
    nb_operators = logicExpression.count("||") + logicExpression.count("&&")
    nb_groups = nb_operators + 1
    total_elements = nb_groups + nb_operators

    tab = [[] for i in range(total_elements)]
    
    i = 0
    
    for op in logicExpression.split(' '):
        if op == "&&" or op == "||":
            i += 1
            tab[i] = op
            i += 1
        else:
            tab[i].append(op)
    return tab



def is_valid_cve_by_logic_tab(cve: dict, logicTab: list):
    result = None
    cond = None
    next_op = None
    
    for expr in logicTab:
        if expr not in ["&&", "||"]:
            field, op, value = expr[0], expr[1], expr[2].strip('"\'[]').split(',')
            value = [v.strip() for v in value]
            field_val = cve[field]

            if op == "==":
                cond = field_val == value[0] if not isinstance(field_val, list) else value[0] in field_val
            elif op == ":=":
                if isinstance(field_val, list):
                    cond = any(v in field_val for v in value)
                else:
                    cond = any(v in str(field_val) for v in value)
            elif op == "!=":
                cond = field_val != value[0] if not isinstance(field_val, list) else value[0] not in field_val
            elif op == "!:=":
                if isinstance(field_val, list):
                    cond = not any(v in field_val for v in value)
                else:
                    cond = not any(v in str(field_val) for v in value)
            elif op == ">":
                cond = float(field_val) > float(value[0])
            elif op == "<":
                cond = float(field_val) < float(value[0])
            elif op == ">=":
                cond = float(field_val) >= float(value[0])
            elif op == "<=":
                cond = float(field_val) <= float(value[0])
            
            # Appliquer l'opérateur précédent si existe
            if result is None:
                result = cond
            elif next_op == "||":
                result = result or cond
            elif next_op == "&&":
                result = result and cond
            
            next_op = None
        
        else:
            # Stocker l'opérateur pour la prochaine condition
            next_op = expr

    return result if result is not None else False


def extract_date_in_expression(logicExpression : str):
    pass