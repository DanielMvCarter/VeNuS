# # # # # 
# # # # import datetime

# # # # now = datetime.datetime.now()
# # # # print(str(now).replace(" ", ":"))

# # # import os, csv
# # # folder = "2022-02-21:13:32:58.858187"
# # # names=[]
# # # # try:
# # # #     for name in os.listdir('scans/'+folder+'/outputs/dfs'):
# # # #         names.append(name.strip("_out.csv"))
# # # #         file = "Apache"
# # # #         with open('scans/'+folder+'/outputs/dfs/'+file+"_out.csv",newline='') as f:
# # # #             output =list(csv.reader(f))
# # # #     print(names)
# # # # except:
# # # for name in os.listdir('scans/'+folder+'/outputs/dfs'):
# # #     names.append(name.strip("_out.csv"))
# # # print("here",names)
# import json
# # presets=json.load(open("presets.txt"))
# # input = 'Metasploitable:192.168.139.129 -A'
# # preset = 'preset1'
# # user_input = input.split(":")
# # presets[preset]["Name"] = user_input[0]
# # presets[preset]["Details"] = user_input[1]
# # # json.dump(presets, open("presets.txt",'w'))
# # print(presets)


# presets=json.load(open("presets.txt"))
# user_input = "Preset name: IP address Flags ".split(":")
# number ="preset"+str(len(presets)+1)
# presets[number]={0}
# # presets[number]={'Name':user_input[0]}
# # presets[number]={'Details:':(" ").join(user_input[1:])}
# second = {number:{'Name':user_input[0],'Details':(" ").join(user_input[1:])}}
# presets.update({number:{'Name':user_input[0],'Details':(" ").join(user_input[1:])}})
# # json.dump(presets, open("presets.txt",'w'))(" ").join(user_input[1:])
# # presets=json.load(open("presets.txt"))
# print(presets)

# import os, csv
# names =[]
# for name in os.listdir('scans/2022-02-21:13:32:58.858187/outputs/dfs'):
#     names.append(name.strip("_out.csv"))
#     file = "Apache"
#     with open('scans/2022-02-21:13:32:58.858187/outputs/dfs/'+file+"_out.csv",newline='') as f:
#         output =list(csv.reader(f))
#         output.pop(0)
# print(output)

# import datetime

# now =datetime.datetime.now().strftime("%H:%M|%m/%d/%Y")
# now =now
# print(now)

import pandas as pd
import matplotlib.pyplot as plt
import os

def load_csv_data(file,folder):
    data = pd.read_csv('scans/'+folder+'/outputs/dfs/'+file)
    return data

total_data =[]
folder="Scan2"

for file in os.listdir('scans/'+folder+'/outputs/dfs'):
    data = load_csv_data(file,folder)
    total_data.append(data)
total_data = pd.concat(total_data)
critical =total_data.sort_values(by=['cvss'], ascending=False)[:5]
# critical.drop(columns=['Unnamed:'])
critical.drop(columns=['Unnamed: 0'])
# print(critical)#.to_csv('critical_out.csv')