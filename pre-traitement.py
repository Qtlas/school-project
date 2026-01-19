import os
import json
from main import *

for dirName in os.listdir("opencve-kb"):
    new_path = f"db/{dirName}"
    if not os.path.exists(new_path):
        os.makedirs(new_path)
    for cveName in os.listdir(f"opencve-kb/{dirName}"): 
        filePath = f"opencve-kb/{dirName}/" + cveName
        data = json_to_dict(filePath)
        #rint(data["nvd"]["weaknesses"])
        with open(new_path + "/" + cveName, 'w') as f:
            new_data = {k : search_by(data, k) for k in SEARCH_DICT}
            f.write(json.dumps(new_data))
            #print(new_data)
