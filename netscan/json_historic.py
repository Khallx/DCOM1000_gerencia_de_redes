import json # to manipulate json file

# load json file, return list 
def load_historic(file_name):
  with open(file_name) as json_file: 
    return json.load(json_file) 
  
# print the json file
def print_historic_file(file):
  print(json.dumps(file, indent=4))

# verify if mac addres existis in historic
def verify_if_exists(file,mac):
  for i in range(len(file)):
    if file[i]["MAC"] == mac:
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
    print("Os dados do MAC: "+data["MAC"]+" foram adicionados")

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
      if json_data[i]["ONLINE"] != data["ONLINE"]:
        json_data[i]["ONLINE"] = data["ONLINE"]
      if json_data[i]["VENDOR"] != data["VENDOR"]:
        json_data[i]["VENDOR"] = data["VENDOR"]
      if json_data[i]["ROUTER"] != data["ROUTER"]:
        json_data[i]["ROUTER"] = data["ROUTER"]
        
      f.seek(0)
      f.write(json.dumps(json_data,indent=4))
      f.truncate()
      print("Atualizados os dados, do MAC: "+data["MAC"])

  else:
    print("Impossível atualizar, o MAC: "+data["MAC"]
    +", inexistente no histórico")

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

if __name__ == "__main__":
  
  #set json file name
  historic_file = 'data.json'
   
  #print_historic_file(load_historic(historic_file))
  
  new_device = {
    "IP": "192.168.1.150",
    "MAC": "88:34:93:79:14:10",
    "ONLINE": "True",
    "VENDOR": "Intelbras",
    "ROUTER": "True",
    "FSCAN_DATE": "21/11/2020 22:15:21"
    }

  tmp_scanned_device = {
    "IP": "192.168.1.120",
    "MAC": "14:2d:27:cd:52:dd",
    "ONLINE": "True",
    "VENDOR": "Intelbras TLW88",
    "ROUTER": "True",
    "FSCAN_DATE": "21/11/2020 22:15:21"
  }

  add_to_historic(historic_file,new_device)

  update_historic(historic_file,tmp_scanned_device)

  #remove_of_historic(historic_file,new_device)
