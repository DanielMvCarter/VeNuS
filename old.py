import ftplib

class ftp:
    @staticmethod
    def downloadFiles(ftpCon):
        outputFile = open("output.txt", "a")
        outputFile.write("\nFTP Files Downloaded: \n")
        #Get ftp server file information
        for i in ftpCon.nlst():
            files = ftpCon.nlst()
            with open(i, "wb") as file:
            # use FTP's RETR command to download the file
                ftpCon.retrbinary(f"RETR {i}", file.write)
            print(f"Downloaded file: {i}")
            outputFile.write(f"{i}\n")
            ##################### Move or find out how to download to specific location /outputs/ftpFiles
    @staticmethod
    def ftpQuit(ftpCon):
        ftpCon.quit()

    @staticmethod
    def Login():
        method = input("How would you like to log in? Anon(1), Wordlist(2), Brute(3)\n--> ")
        ftpUser=""
        ftpPassword=""
        if method == "1":  # Log in anonymously
            ftpUser = "anonymous"
            ftpPassword = "anonymous"
        elif method == "2":  # Log in with a wordlist
            print("wordlist")
        elif method == "3":  # Log in via Brute Force
            print("Brute Force")
        else:
            print("Invalid input")
        # Connect to the FTP server with the user and password    
        ftpCon = ftplib.FTP(SG.ip_addr, ftpUser,ftpPassword)
        ftpCon.encoding = "utf-8"
        ftp.downloadFiles(ftpCon)
    
    @staticmethod
    def checkPorts():
        print("Checking Nmap results for FTP server")  # Finding ftp ports
        outputFile = open("output.txt", "r")
        # Loop through the file line by line
        for line in outputFile:
            if "ftp" in line:  # Checking there is an FTP port
                print('FTP server found')
                ftp.Login()
        outputFile.close()