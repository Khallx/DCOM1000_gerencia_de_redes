# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json # to manipulate json file

# load json file, return list 
def load_historic(file_name):
  with open(file_name) as json_file: 
    return json.load(json_file) 
  
# print the json file
def print_historic_file(file_name):
  print(json.dumps(file_name, indent=4))

# verify if mac addres existis in historic
def verify_if_exists(file_name,mac):
  for i in range(len(file_name)):
    if file_name[i]["MAC"] == mac:
      return True,i
      break
    
  return False,None 

# add device information in historic   
def add_to_historic(file_name,data):
  v,i = verify_if_exists(load_historic(file_name),data["MAC"])
  if not v:
    with open(file_name, 'r+') as f:
        json_data = json.load(f)

        json_data.append(data)

        f.seek(0)
        f.write(json.dumps(json_data,indent=4))
        f.truncate()
    #print("Os dados do MAC: "+data["MAC"]+" foram adicionados")

  else : 
    print("Impossível adicionar, o MAC: "+data["MAC"]
    +", já existe no histórico")

# update device information in historic   
def update_historic(file_name,data): 
  v,i =verify_if_exists(load_historic(file_name),data["MAC"])
  if v:
    with open(file_name, 'r+') as f:
      json_data = json.load(f)
      
      if json_data[i]["IP"] != data["IP"]:
        json_data[i]["IP"] = data["IP"]
      if json_data[i]["UP"] != data["UP"]:
        json_data[i]["UP"] = data["UP"]
      if json_data[i]["VENDOR"] != data["VENDOR"]:
        json_data[i]["VENDOR"] = data["VENDOR"]
      if json_data[i]["ROUTER"] != data["ROUTER"]:
        json_data[i]["ROUTER"] = data["ROUTER"]
        
      f.seek(0)
      f.write(json.dumps(json_data,indent=4))
      f.truncate()
      #print("Atualizados os dados, do MAC: "+data["MAC"])

  else:
    add_to_historic(file_name,data)

# remove device information of historic   
def remove_of_historic(file_name,data):   
  v,i =verify_if_exists(load_historic(file_name),data["MAC"])
  if v:
    with open(file_name, 'r+') as f:
      json_data = json.load(f)
      
      del json_data[i]

      f.seek(0)
      f.write(json.dumps(json_data,indent=4))
      f.truncate()
    print("Removidos os registros do MAC: "+data["MAC"])
  else : 
    print("Impossível remover, o MAC: "+data["MAC"]
    +", inexistente no histórico")
