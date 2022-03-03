import os, ipaddress, json
from scanners import NetScan, VulnScan, SolScan,Reporting


def init_system():
    try:
        os.path.isdir('outputs')
    except:
        os.system('mkdir outputs')
    try:
        os.path.isdir('outputs/clean')
    except:
        os.system('mkdir outputs/clean')
    try:
        os.path.isdir('scans/')
    except:
        os.system('mkdir scans/')
    #command = ('sudo apt install nmap')
    #os.system(command)

def input_valid(input):
    try: 
        input=input.split(" ")
        ipaddress.ip_address(input[0])
        if input[1] == "Standard":
            input = input[0]+ " -A"
        elif input[1] == "Light":
            input = input[0]+ " -A -T0 -sV --version-light"
        else:
            input = input[0]+" -A -T4 -sV --version-all"
        return input
    except:
        try:
            presets=json.load(open("presets.txt"))
            for preset in presets:
                if input in presets[preset]["Name"]:
                    input = presets[preset]["Details"]
            return input
        except:
            flags= ["-sL","-sn","-Pn","-PS","-PA","-PU","-PY","-PE","-PP","-PM","-n","-R","-sS","-sT","-sA","-sW" "-sM","-sU","-sN","-sF","-sX","-sY","-sZ","-sO","-F","-r","-sV","--version-light","--version-all","--version-trace","-sC","-O","--osscan-limit","--osscan-guess","--min-rtt-timeout","--max-rtt-timeout","-f,""-oN","-oX","-oS","-d"]
            check =[]
            for i in input:
                check.append(i)
            check.pop(0)
            for flag in check:
                #Check if the flag exists in the list, if not it is invalid
                if flag not in flags:
                    return "Invalid"
            input = " ".join(input)
            return input

def scan(input):
    init_system()
    netScan = NetScan(input_valid(input))
    netScan.run()
    vulnScan = VulnScan(netScan.ip_addr,netScan.versions)
    vulnScan.run()
    solScan = SolScan()
    solScan.process_vulners()
    solScan.run()
    
def reporting(input):
    report=Reporting(input)
    report.save()
    report.total_data()
    report.create_bar()
    report.priority()

# report=Reporting('besakdjw')
# report.save()
# report.total_data()
# report.criticalVulns()