###################################
# File Name :tools
# Purpose : This file contains classes for each tool that will be called  
#
# Created by    : Daniel Carter
# Date created  : 25//08/21
###################################

import os, csv ,re,ipaddress, requests, json
import multiprocessing as mp
from bs4 import BeautifulSoup
from pandas import DataFrame

###################################
# Class Name :NetScan
# Purpose : This class contains all of the functionality for the network scanning portion.
# This is done through nmap (more information found at https://nmap.org).
# Allows for a user to input to the program and create presets.
# Created by    : Daniel Carter
# Date created  : 25/08/21
###################################
class NetScan:
    def __init__(self,input):
        self.user_input=""
        self.ip_addr=""
        self.flags=""
        self.versions=[]
        self.input = input

    #This function drives the network scanning        
    def run(self):
        self.usr_input()
        self.exec()
        self.process()

    #Take the user input, firstly check if they want a custom or preset preset
    def usr_input(self):
        try: 
            self.user_input=self.input
            self.input=self.input.split(" ")
            ipaddress.ip_address(self.input[0])
            self.ip_addr=self.input[0]
        except:
            presets=json.load(open("presets.txt"))
            for preset in presets:
                if self.input in presets[preset]["Name"]:
                    self.input = presets[preset]["Details"]

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


    #Process the network scan results
    def process(self):
        #Create a command to search the nmap output file and return found ports
        command = ('grep -w "open" outputs/nmap.txt > outputs/clean/nmap.csv')
        os.system(command)
        self.get_versions()
    
    #A function to extract the running services from the nmap scan
    def get_versions(self):
        #Keywords placed after the version which are redundant for futher work.
        key_words = ["(workgroup:","WORKGROUP)","Ubuntu", "Debian","((Ubuntu)", "DAV/2)","8ubuntu1", "(protocol 2.0)","(access", "denied)"]
        with open("outputs/clean/nmap.csv", 'r') as file:
            scan = list(csv.reader(file))
            file.close()
        splitVersion=[]
        #Take just the information after service
        for i in scan:
            splitVersion.append(str(i[0]).split()[3:])
        for word in splitVersion:
            j=0
            stopwords=[]
            #Go through the row and append until a keyword is found
            while j < len(word):
                if word[j] in key_words:
                    break
                stopwords.append(word[j])
                j+=1
            self.versions.append(" ".join(stopwords))
        
    #A function to run the initial nmap scan
    def exec(self):
        command = ('nmap -oN outputs/nmap.txt '+ self.user_input) 
        os.system(command)

###################################
# Class Name :VulnScan
# Purpose : This class contains all of the functionality for the vulnerability scanning portion.
# Makes use of various vuln scanning tools including vulners (more information found at https://vulners.com/),
# vuln (more information found at https://nmap.org/nsedoc/categories/vuln.html) 
# and searchsploit (more information found at https://www.exploit-db.com/searchsploit).
# This will take outputs from the network scanning functions, pass the information to the new tools and output
# these results into files in the "outputs" directory.
# Created by    : Daniel Carter
# Date created  : 01/02/22
###################################
class VulnScan:
    def __init__(self,ip_addr,version):
        self.ip_addr=ip_addr
        self.versions=version

    def threading(self):
        # thread1= mp.Process(target=self.vuln())
        # thread1.start()
        # thread2= mp.Process(target=self.searchsploit())
        # thread2.start()
        thread3=mp.Process(target=self.vulners())
        thread3.start()
        # thread1.join()
        # thread2.join()
        thread3.join()

    def run(self):
        self.threading()

    def vuln(self):
        command ='echo "kali" |sudo -S nmap --script vuln '+ self.ip_addr +' > outputs/vuln.txt'
        os.system(command)

    def vulners(self):
        command ='nmap -sV --script vulners '+ self.ip_addr +' > outputs/vulners.txt'
        os.system(command)

    def searchsploit(self):
        for version in self.versions:
            command = ('searchsploit "'+version+'" >> outputs/searchsploit.txt')
            os.system(command)
    
    def nasl(self,given_dir):
        command = 'cp '+ given_dir + ' /home/kali/Desktop/NVaSS/naslScripts'
        os.system(command)

###################################
# Class Name :SolScan
# Purpose : This class contains all of the functionality for the solution scanning portion.
# This will process the output files from the vulnScan class, and use the CVEs identified to scrape
# various databases to find CVE descriptions and patches for them.
# Created by    : Daniel Carter
# Date created  : 10/02/22
###################################
class SolScan:
    def __init__(self):
        self.serVulns = []
        
    def run(self):
        self.cveDesc()
        self.cvePatch()
        self.write_cveCSV()
    #Process the network scan results
    def process_vulners(self):
        print("Processing Vulners")
        vuln=[]
        serviceInfo=[]
        with open("outputs/vulners.txt") as scan:
            lines= scan.readlines()
        scan.close()
        for i,row in enumerate(lines):
            if i ==len(lines)-1:
                break
            #If CVEs are found for the service then save the previous block
            if "vulners:" in lines[i+1]:
                serviceInfo.append(vuln)
                vuln=[]
                #Some instances of services have subheadings so save previous line
                if "|_h" in row:
                    vuln.append(lines[i-1])
            vuln.append(row)
            #Finding the end of the file and writing final block
            if "Nmap done:" in lines[i+1]:
                serviceInfo.append(vuln)
                break
        #The first element is scan information- drop as irrelevant
        serviceInfo.pop(0)
        for block in serviceInfo:
            #Retrieve the service name
            df = DataFrame()
            df.name =  ((" ".join(block[0].split()[3:])))
            cve = []
            cvss = []
            for row in block:
                #If there is a CVE in the row split and see if it is start of row
                if "CVE" in row:
                    row=row.split("\t")
                    if re.match(r'^CVE',row[1]):
                        cve.append(row[1])
                        cvss.append(row[2])
            df['cve']=cve
            df['cvss']=cvss
            self.serVulns.append(df)

    #A function to scrape the web to find descriptions for the CVEs
    def cveDesc(self):
        print("Scraping for Descriptions")
        descs=[]
        #Loop through the array for dataframes taking the CVE out
        for service in range(len(self.serVulns)):
            for cve in self.serVulns[service].cve:
                #Create a get request for each cve webpage
                url = 'https://nvd.nist.gov/vuln/detail/'+cve
                result = requests.get(url)
                #Pass through Beautiful soup and search for <p>
                page = BeautifulSoup(result.text, "html.parser")
                text = page.find_all("p",text=True)
                for j in text:
                    #Search for the vuln-description block
                    tags = str(j).split('"')
                    if "vuln-description" in tags:
                        #Use BeautifulSoup string interpreter to remove html formatting
                        descs.append(j.string)
            # Append all descriptions to the dataframe.
            self.serVulns[service]['desc']= descs
            descs=[]

    def cvePatch(self):
        print("Scraping for Patches")
        patches=[]
        #Loop through the array for dataframes taking the CVE out
        for service in range(len(self.serVulns)):
            for cve in self.serVulns[service].cve:
                #Track if a patch has been found for the cve
                noPatches = len(patches)
                #Create a get request for each cve webpage
                url = 'https://nvd.nist.gov/vuln/detail/'+cve
                result = requests.get(url)
                #Pass through Beautiful soup and search for <td>
                page = BeautifulSoup(result.text, "html.parser")
                text = page.find_all("td")
                for i in text:
                    #Search for a <td> which has a "Patch" in it
                    tags = str(i).split('>')
                    if "Patch</span" in tags:
                        check = tags[0].split("data-testid")
                        #The patches' link is in a related tag but different name so rename
                        if len(check) ==2:
                            realTag = tags[0].replace("resType","link")
                #The first td tag encaptures all subsequent tags so drop and search individually.
                text.pop(0)
                #Re-search through the html with the identified tag
                for i in text:
                    if realTag in str(i):
                        #Once the tag has been found extract the link and append
                        link = " ".join(str(i).split(realTag)).split('"')
                        patches.append(link[1])
                #If no patch has been appended then none were found on the page.
                if noPatches == (len(patches)):
                    patches.append("No Patch Identified")
            #Append the patches to the dataframes
            self.serVulns[service]['Patch']= patches
            patches=[]

    #A function to write the dataframes to their respective output csvs
    def write_cveCSV(self):
        print("Writing CSV")
        for service in range(len(self.serVulns)):
            name =self.serVulns[service].name.split(" ")[0]
            os.system('touch outputs/dfs/'+name+'_out.csv')
            self.serVulns[service].to_csv('outputs/dfs/'+name+'_out.csv')

class Reporting:
    def __init__(self):
        self.serVulns = []