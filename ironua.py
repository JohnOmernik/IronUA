#!/usr/bin/python

import sys
import re
import hashlib
from ironrules import tagrules
from ironrules import uarules
 
 
#######
#Mongo Connectivity
# If enable Commonality != 1 then it won't try to load Mongo stuff or check how common a UA is.
# This is good for pure rule testing
# The schema and setup for Mongo will be documented soon.
 
enableCommonality = 0
 

if enableCommonality == 1:
    import pymongo
    mongoserver = '127.0.0.1'
    mongoport = 27017
    mongo = pymongo.Connection(mongoserver, mongoport)
    mongo_db = mongo['useragent']
    useragent = mongo_db['ua_lookup']
 
 
def main():
 
    testuas = [
"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.76 Safari/537.36",
"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)",
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.0.30729; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)",
"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.102 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.102 Safari/537.36",
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729)",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.77 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.102 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:24.0) Gecko/20100101 Firefox/24.0",
"Mozilla/5.0 (Windows NT 5.1; rv:26.0) Gecko/20100101 Firefox/26.0",
"Mozilla/4.0 (compatible; MSIE 8.0; Windows XP; Trident/4.0; .NET CLR 2.0.50727)",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.76 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; rv:27.0) Gecko/20100101 Firefox/27.0",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:14.0) Gecko/20100101 Firefox/14.0.1",
"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0",
"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; Touch; MAGWJS)",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; rv:26.0) Gecko/20100101 Firefox/26.0",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.102 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/31.0.1650.63 Safari/537.36",
"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0",
"SchwabMobileForAndroid/3.3.0.25 (Android 4.1.2; XT907 Build/9.8.1Q-94-1; en-us)",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/29.0.1547.65 Safari/537.36",
"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.102 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:25.0) Gecko/20100101 Firefox/25.0",
"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.102 Safari/537.36",
"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0; MATBJS)",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.102 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; rv:25.0) Gecko/20100101 Firefox/25.0",
"Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20100101 Firefox/12.0",
"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.102 Safari/537.36 OPR/19.0.1326.59",
"Mozilla/5.0 (Windows NT 5.2) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.76 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.76 Safari/537.36 OPR/19.0.1326.56",
"Mozilla/5.0 (Windows NT 5.2; rv:26.0) Gecko/20100101 Firefox/26.0",
"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/534.57.2 (KHTML  like Gecko) Version/5.1.7 Safari/534.57.2",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/30.0.1599.101 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/534.57.7 (KHTML  like Gecko) Version/5.1.7 Safari/534.57.7",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.76 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.76 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0",
"Mozilla/5.0+(Windows+NT+5.1)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/32.0.1700.102+Safari/537.36+OPR/19.0.1326.59",
"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0",
"Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1820.2 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
"Mozilla/5.0 (Windows NT 5.2; rv:27.0) Gecko/20100101 Firefox/27.0",
"Mozilla/5.0 (Windows NT 5.2) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.102 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/29.0.1547.62 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/30.0.1599.66 Safari/537.36",
"Mozilla/5.0 (Linux; U; Android 4.1.2; en-us; SAMSUNG-SGH-I317 Build/JZO54K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
"Mozilla/5.0 (Linux; Android 4.1.2; XT907 Build/9.8.1Q-94-1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.99 Mobile Safari/537.36",
"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; WOW64; Trident/5.0; MDDRJS)",
"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; .NET CLR 2.0.50727; WOW64; .NET CLR 2.0.50727; Trident/6.0; MAGWJS)",
"Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
"75.38.188.37-1391500596503",
"Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)",
"Mozilla/5.0 (iPad; CPU OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53",
"Mozilla/5.0 (iPhone; CPU iPhone OS 7_0_2 like Mac OS X) AppleWebKit/537.51.1 (KHTML  like Gecko) Version/7.0 Mobile/11A501 Safari/9537.53",
"Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; LS670 Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.73.11 (KHTML, like Gecko) Version/7.0.1 Safari/537.73.11",
"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36 OPR/18.0.1284.68",
"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.76 Safari/537.36",
"Mozilla/5.0 (Windows NT 5.1; rv:16.0) Gecko/20100101 Firefox/16.0",
"Mozilla/5.0 (Windows NT 5.1; rv:24.0) Gecko/20100101 Firefox/24.0",
"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.76 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; rv: 24.0) Gecko/20120205 Firefox/24.0",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36 OPR/18.0.1284.68",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36 OPR/18.0.1284.68",
"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"SchwabMobile/3.3.0.122 (iPhone OS 7.0.4; iPhone5,1; en_CA)",
"SchwabMobile/3.3.0.122 (iPhone OS 7.0.4; iPhone5,2; en_NG)",
"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.107 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0",
"Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; MATBJS; rv:11.0) like Gecko",
"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.76 Safari/537.36",
"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; MDDCJS; rv:11.0) like Gecko"
]
 
    testuas = [
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727)',
        'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows XP; Trident/4.0; .NET CLR 2.0.50727)',
        'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.0.30729; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
        'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)',
        'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36 OPR/18.0.1284.68',
        'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML like Gecko) Chrome/32.0.1700.102 Safari/537.36 OPR/19.0.1326.59',
        'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML like Gecko) Chrome/32.0.1700.107 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML like Gecko) Chrome/32.0.1700.107 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.76 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.102 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.102 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.107 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.77 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/32.0.1700.102 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:24.0) Gecko/20100101 Firefox/24.0',
        'Mozilla/5.0 (Windows NT 5.1; rv:26.0) Gecko/20100101 Firefox/26.0',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0'
    ]
 
   # testuas = ['Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; AT T CSM6.0; AT T CSM 6; FunWebProducts; AT T CSM7.0; EntryProtect/5.6.0.7872; PhishLock/4.2.0.7869; EntryProtect/5.6.0.8012; PhishLock/4.2.0.8207; EntryProtect/5.6.0.8731; PhishLock/4.2.0.873']

    testuas = ['Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)']

    aday = '2014-01-13'

 
 
 
 
 
# hacky ability to determine only what you want to print for testing.
 
    #1 = Print, 0 = Don't print, -1 = exclude
    pInv = 1
    pInf = 1
    pNoTags = 1
    pFilter = 0
 
    fil = ['inf:schwabmobile', 'inf:schwabmobile_android', 'inf:valid_firefox', 'inf:valid_new_opera', 'inf:valid_chrome', 'inf:valid_safari']
 
    for ua in testuas:
        tags = []
        tags = tagUserAgent(ua)
 
        p = 0
        if not tags:
            if pNoTags == 1:
                p = 1
            elif pNoTags <= 0:
               p = -1
        else:
            for tag in tags:
                if tag.find("inf") == 0:
                    if pInf == 1:
                        p = 1
                    elif pInf == -1:
                        p = -1
                        break
                if tag.find("inv") == 0:
                    if pInv == 1:
                        p = 1
                    elif pInv == -1:
                        p = -1
                        break
                if pFilter != 0:
                    for f in fil:
                        if tag.find(f) == 0:
                            if pFilter == 1:
                                p = 1
                            elif pFilter == -1:
                                p = -1
                                break
                if p == -1:
                    break
 
### Pretty output for testing. Of course, this file can be included and you can use the output of the tagUserAgent as a list of tags programatically
        if p == 1:
            prettyPrint(prettyReturn(ua, aday, tags))        
######
# Returns a formated string

def prettyReturn(ua, day, tags):
    infHead = 0
    invHead = 0
    ret = ""
    ret =  "\n--------------------\nUserAgent: %s\n" % ua
    if day != '':
        common = howCommon(ua, day)
    else:
        common = {}
        common['status'] = "Disabled"

    #common = {'status':'Not Found'}
    if common['status'] == "Found":
        ret = ret + "\tUser Agent Commonality: Found in DB for %s\n" % day
        ret = ret + "\tNumber of Logons with UA: %s - Percentage of Total Logins for Day %s\n" % (common['total_logins'], common['total_logins_perc'])
        ret = ret + "\tNumber of Login IDs with UA: %s - Percentage of Total Login IDs for Day %s\n" % (common['total_loginids'], common['total_loginids_perc'])
        ret = ret + "\tNumber of Computers with UA: %s - Percentage of Total Computers for Day %s\n" % (common['total_computers'], common['total_computers_perc'])
        ret = ret + "\tNumber of IPs with UA: %s - Percentage of Total IPs for Day %s\n" % (common['total_ips'], common['total_ips_perc'])
        ret = ret + "\n"
    elif common['status'] == "Disabled":
        ret = ret + "\tCommonality Disabled\n"
    else:
        ret = ret + "\tUser Agent Commonality: Not Found in DB for %s\n" % day
        ret = ret + "\n"
 
    for t in tags:
        if t.find('inf:') == 0:
            if infHead == 0:
                infHead = 1
                ret = ret + "\tInformational Components:\n"
            ret = ret + "\t\tTag: %s - %s\n" % (t, retDescbyTag(t))
    for t in tags:
        if t.find('inv:') == 0:
            if invHead == 0:
                invHead = 1
                ret = ret + "\n\tInvalid Components:\n"
            ret = ret + "\t\tTag: %s - %s\n" % (t, retDescbyTag(t))
    return ret 
#################################################################################
# prettyPrint(strOutput)
# Takes the output of prettyReturn and prints it
 
 
def prettyPrint(strOutput):
    print strOutput
 
 
################################################
# Process the tag rules
# Append rules that match and return all the tags
 
def processTags(tags):
    retTags = tags
    for tagrule in tagrules:
        if eval(tagrule['rule']):
            retTags.append(tagrule['tag'])
    return retTags
 
 
##############################################
# First run the UA tags on the useragnet
# Then process the Tag rules and append those.
# return the Tag list
def tagUserAgent(useragent):
 
    oTags = []
    for rule in uarules:
        m = re.search(rule['re'], useragent)
        if "neg" in rule:
            if not m:
                oTags.append(rule['tag'])
        else:
            if m:
                oTags.append(rule['tag'])
        m = None
    oTags = processTags(oTags) 
    return oTags
 
################################################
# Allows a quick lookup of the Description of a tag by the tag value
#
def retDescbyTag(tag):
    ret = "Tag Not Found"
    for rule in uarules:
        if rule['tag'] == tag:
            ret = rule['desc']
            break
    if ret == "Tag Not Found":
        for rule in tagrules:
            if rule['tag'] == tag:
                ret = rule['desc']
                break      
    return ret
 
 
###############################################################
# This is the function that connects to Mongo DB and looks up a the commoanlity of the snow
def howCommon(ua, day):
    ret = {}
    if enableCommonality == 1:
        uahash = hashlib.md5(ua).hexdigest()
        cur = useragent.find_one({"day":day, "user_agent_md5":uahash})
        if cur != None:
            ret["status"] = "Found"
            ret["total_logins"] = cur["total_logins"]
            ret["total_logins_perc"] = cur["total_logins_perc"]
            ret["total_loginids"] = cur["total_loginids"]
            ret["total_loginids_perc"] = cur["total_loginids_perc"]
            ret["total_computers"] = cur["total_computers"]
            ret["total_computers_perc"] = cur["total_computers_perc"]
            ret["total_ips"] = cur["total_ips"]
            ret["total_ips_perc"] = cur["total_ips_perc"]
        else:
            ret['status'] = "Not Found"
            ret["total_logins"] = ""
            ret["total_logins_perc"] = ""
            ret["total_loginids"] = ""
            ret["total_loginids_perc"] = ""
            ret["total_computers"] = ""
            ret["total_computers_perc"] = ""
            ret["total_ips"] = ""
            ret["total_ips_perc"] = ""
    else:
        ret['status'] = "Not Found"
        ret["total_logins"] = ""
        ret["total_logins_perc"] = ""
        ret["total_loginids"] = ""
        ret["total_loginids_perc"] = ""
        ret["total_computers"] = ""
        ret["total_computers_perc"] = ""
        ret["total_ips"] = ""
        ret["total_ips_perc"] = ""
    return ret
 
 
 
 
 
if __name__ == '__main__':
    main()
