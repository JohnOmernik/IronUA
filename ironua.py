import re
import sys
import json
import ironua

# some standards: 
# ip = IP Address
# symbol = Stock Symblie
# Date format (output) YYYY-MM-DD so if it's different, we try to fix it. 
# useragent = Browser User Agent
# Globals Settings

bRemoveDupDates = 1 # If multiple dates are listed, then remove duplicates (if set to 1) otherwise leave them in. 

# Main Section of code, this is what runs 
def main():
#   print "Hello"
    datadict = parseCyfastStats("20140218_cyfast.txt")
    #print datadict
    for x in datadict['UserAgent']:
        tags = []
        tags = ironua.tagUserAgent(x['useragent'])
        ironua.prettyPrint(x['useragent'], '2014-02-10', tags)

        #print '"%s",' % x['useragent']
    


#   print json.dumps(datadict, sort_keys=True, indent=4)

# Takes a filename, and produces a big dictionary of the data there, this allows us to then send the dictionary to validators, additional looksup, and outputers/formaters

def parseCyfastStats(inFile):
    # Keeps track of which section we are in
    inval = ""
    # The returned dictionary of data
    datadict = {}
    # The various sections of data
    Top10IPs = []
    Top10Volume = []
    UniqueSymbols = []
    UserAgent = []
    CyFinIPMatch = []
    # Open the file
    f = open(inFile, "r")
    # Loop through and do something
    for line in f:
        line = line.rstrip('\r\n')
        if inval == "":
            if line.find('New FI_Intel Records') == 0:
                inval = "NewFI"
            if line.find('New Cyber_Intel Records') == 0:
                inval = "NewCyberIntel"
            if line.find('Top 10 Probe IPs') == 0:
                inval = "Top10IPs"
            if line.find('Unique Symbols') == 0:
                inval = "UniqueSymbols"
            if line.find('Total Volume (Shares)') == 0:
                inval = "TotalVolume"
            if line.find('Top 10 Volume (Shares)') == 0:
                inval = "Top10Volume"
            if line.find('User Agent') == 0:
                inval = "UserAgent"
            if line.find('CyFin IP Match') == 0:
                inval = "CyFinIPMatch"
        else:
            if inval == "NewFI":
                datadict['NewFI'] = line
                inval = ""
            elif inval == "NewCyberIntel":
                datadict['NewCyberIntel'] = line
                inval = ""
            elif inval == "Top10IPs":
                if line.strip() == "":
                    inval = ""
                    datadict["Top10IPs"] = Top10IPs
                else:
                    dAr = line.split("\t")
                    tD = {}
                    tD['ip'] = dAr[0]
                    tD['count'] = dAr[2]
                    tD['overallcount'] = dAr[3]
                    Top10IPs.append(tD)
    
            elif inval == "UniqueSymbols":
                if line.strip() == "":
                    inval = ""
                    datadict["UniqueSymbols"] = UniqueSymbols
                else:
                    dAr = line.split("\t")
                    tD = {}
                    tD['symbol'] = dAr[0]
                    tD['count'] = dAr[2]
                    #h = [y[2]+"-"+y[0]+"-"+y[1] for y in [x.strip().split("/") for x in dAr[3].split(",")]]
                    #print h
                    if bRemoveDupDates == 1:
                        h = sorted(set([y[2]+"-"+y[0]+"-"+y[1] for y in [x.strip().split("/") for x in dAr[3].split(",")]]))
                    else:
                        h = sorted([y[2]+"-"+y[0]+"-"+y[1] for y in [x.strip().split("/") for x in dAr[3].split(",")]])
    
                    d = ",".join(h)
                    tD['dates'] = d
                    UniqueSymbols.append(tD) 
            elif inval == "TotalVolume":
                datadict['TotalVolume'] = line
                inval = ""
            elif inval == "Top10Volume":
                if line.strip() == "":
                    inval = ""
                    datadict["Top10Volume"] = Top10Volume
                else:
                    dAr = line.split("\t")
                    tD = {}
                    tD['symbol'] = dAr[0]
                    tD['shares'] = dAr[1]
                    Top10Volume.append(tD)
            elif inval == "UserAgent":
                if line.strip() == "":
                    inval = ""
                    datadict['UserAgent'] = UserAgent
                else:
                    dAr = line.split("\t")
                    tD = {}
                    tD['useragent'] = dAr[0]
                    tD['count'] = dAr[1]
                    UserAgent.append(tD)
            elif inval == "CyFinIPMatch":
                if line.strip() == "":
                    inval = ""
                    datadict['CyFinIPMatch'] = CyFinIPMatch
                else:
                    dAr = line.split("\t")
                    tD = {}
                    tD['ip'] = dAr[0]
                    tD['count'] = dAr[1]
                    tD['firstreported'] = dAr[2]
                    tD['lastreported'] = dAr[3]
                    tD['link'] = dAr[4]
                    CyFinIPMatch.append(tD)
    f.close()
    return datadict


if __name__ == '__main__':
    main()

