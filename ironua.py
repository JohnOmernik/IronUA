import sys
import re
import hashlib



#######
#Mongo Connectivity
# If enable Commonality != 1 then it won't try to load Mongo stuff or check how common a UA is. 
# This is good for pure rule testing
# The schema and setup for Mongo will be documented soon. 

enableCommonality = 1

# Tag based rules. Rules are in "Python" syntax, basically looking for the presence or lack of presence of tags in the tags collection, and if that condition is met, add a tag. 
tagrules = [ 
    {"rule":"'inf:new_opera' in tags and not ('inf:valid_safari' in tags or 'inf:valid_chrome' in tags or 'inf:valid_new_opera' in tags)", "tag":"inv:new_opera", "desc":"New Opera Token string but does not include valid Safari, Chrome, or Opera string"},
    {"rule":"'inf:chrome' in tags and not ('inf:valid_safari' in tags or 'inf:valid_chrome' in tags or 'inf:valid_new_opera' in tags)", "tag":"inv:chrome", "desc":"Chrome Token string but does not include valid Safari, Chrome, or Opera string"},
    {"rule":"'inf:safari' in tags and not ('inf:valid_safari' in tags or 'inf:valid_chrome' in tags or 'inf:valid_new_opera' in tags)", "tag":"inv:safari", "desc":"Safari Token string but does not include valid Safari, Chrome, or Opera string"},
    {"rule":"'inf:mobile_safari' in tags and not ('inf:valid_mobile_safari' in tags)", "tag":"inv:mobile_safari", "desc":"Mobile Safari Token string but does not include valid Mobile Safari UA"},
    {"rule":"not 'inf:valid_firefox' in tags and 'inf:firefox' in tags", "tag":"inv:filefox", "desc":"Firefox token in string but does not include valid firefox string"},
    {"rule":"'inf:mozilla_5' in tags and ('inf:msie_5.01' in tags or 'inf:msie_6' in tags or 'inf:msie_7' in tags or 'inf:msie_8' in tags)", "tag":"inv:mozilla_5_w_old_msie", "desc":"Mozilla/5.0 with IE Version less then MSIE 9"}
]


# UA rules are regex based, if the regex matches, it appends the tag.  
# Also, if the key neg exists, than it appends the tag if the reg DOESN'T match. 
# Try to keep these simple if possible, but sometimes complexity is needed

uarules = [
    {"re":"(mozilla|windows nt|msie|firefox|chrome\/|safari)", "tag":"inv:improper_case", "desc":"Tokens identified with improper casing"},
    {"re":"Windows XP", "tag":"inv:windowsxp", "desc":"Windows XP String identified"},
    {"re":"^Mozilla\/5\.0 \((X11; CrOS i686 \d{4}\.\d{2}(\.\d{1,2})?|Windows NT \d.\d(; WOW64)?|Macintosh; Intel Mac OS X \d\d_\d(_\d)?)\) AppleWebKit\/\d{3}\.\d\d \(KHTML, like Gecko\) Chrome\/\d\d\.\d\.\d\d\d\d\.\d\d?\d? Safari\/\d\d\d\.\d\d$", "tag":"inf:valid_chrome", "desc":"Valid Google Chrome UA"},
    {"re":"^Mozilla\/5\.0 \((Windows NT \d.\d(; WOW64)?|Macintosh; Intel Mac OS X \d\d_\d(_\d)?)\) AppleWebKit\/\d{3}\.\d\d(\.\d{1,2})? \(KHTML, like Gecko\) Version\/\d\.\d\.\d Safari\/\d\d\d\.\d\d(\.\d{1,2})?$", "tag":"inf:valid_safari", "desc":"Valid Safari UA"},
    {"re":"\s{2,}", "tag":"inv:extra_spaces", "desc":"Extra spaces in UA make make matching very difficult"},
    {"re":"\(iPad; ", "tag":"inf:ipad", "desc":"iPad Token"},
    {"re":"\(iPod; ", "tag":"inf:ipod", "desc":"iPod Token"},
    {"re":"\(iPhone; ", "tag":"inf:iphone", "desc":"iPhone Token"},
    {"re":" CrOS ", "tag":"inf:chrome_os", "desc":"CrOS - Chrome OS Token"},
    {"re":"Mobile\/[^ ]+ Safari\/\d{4}\.\d{1,2}", "tag":"inf:mobile_safari", "desc":"Mobile Safari Token"},
    {"re":"Mozilla/5.0 \(iP(od|ad|hone); CPU OS \d_\d_\d like Mac OS X\) AppleWebKit\/\d{3}\.\d\d(\.\d{1,2})? \(KHTML, like Gecko\) Version\/\d\.\d Mobile\/[^ ]+ Safari\/\d{4}\.\d{1,2}$", "tag":"inf:valid_mobile_safari", "desc":"Valid Mobile Safari UA"},
    {"re":"^Mozilla\/\d\.\d ", "neg":1, "tag":"inv:no_mozilla", "desc":"Doesn't start with Mozilla"},
    {"re":"^SchwabMobile\/\d", "tag":"inf:schwabmobile", "desc":"Schwabmobile Apps"},
    {"re":"^SchwabMobileForAndroid\/\d", "tag":"inf:schwabmobile_android", "desc":"Schwabmobile For Android app"},
    {"re":"ScottradeMobileApplication \d\.\d(\.\d)?;", "tag":"inf:scotttrade_mobile_app", "desc":"Token for Scott trade mobile applications"},
    {"re":"^Mozilla\/5\.0 \((Windows NT \d.\d;( WOW64;)?|Macintosh; Intel Mac OS X \d\d\.\d;) rv:\d\d\.\d\) Gecko\/\d{8} Firefox\/\d\d\.\d", "tag":"inf:valid_firefox", "desc":"This appears to be a valid Firefox UA"},
    {"re":"Macintosh; Intel Mac OS X \d\d", "tag":"inf:mac", "desc":"Apple Computer"},
    {"re":"^Mozilla\/5\.0 \(Windows NT \d\.\d;?( WOW64)?\) AppleWebKit\/\d{3}\.\d\d \(KHTML, like Gecko\) Chrome\/\d\d\.\d\.\d\d\d\d\.\d\d\d? Safari\/\d\d\d\.\d\d OPR\/\d\d\.\d\.\d{4}\.\d\d$", "tag":"inf:valid_new_opera", "desc":"Valid New Style Opera UA"},
    {"re":"MDDR(JS)?", "tag":"inf:oem_id_dell1", "desc":"Oem Identifier: Possibly Dell"},
    {"re":"MDDC(JS)?", "tag":"inf:oem_id_dell2", "desc":"Oem Identifier: Possibly Dell"},
    {"re":"MAAR(JS)?", "tag":"inf:oem_id_acer_aspire1", "desc":"Oem Identifier: Possibly Acer Aspire"},
    {"re":"MASP(JS)?", "tag":"inf:oem_id_sony1", "desc":"Oem Identifier: Possibly Sony"},
    {"re":"MASA(JS)?", "tag":"inf:oem_id_sony2", "desc":"Oem Identifier: Possibly Sony"},
    {"re":"MDDS(JS)?", "tag":"inf:oem_id_unknown1", "desc":"Oem Identifier: Unknown"},
    {"re":"MAAU(JS)?", "tag":"inf:oem_id_unknown2", "desc":"Oem Identifier: Unknown"},
    {"re":"MASM(JS)?", "tag":"inf:oem_id_samsung1", "desc":"Oem Identifier: Possibly Samsung"},
    {"re":"MALC(JS)?", "tag":"inf:oem_id_lenovo1", "desc":"Oem Identifier: Possibly Lenovo"},
    {"re":"MIDP(JS)?", "tag":"inf:oem_id_unknown3", "desc":"Oem Identifier: Unknown"},
    {"re":"MATM(JS)?", "tag":"inf:oem_id_unknown4", "desc":"Oem Identifier: Unknown"},
    {"re":"MATP(JS)?", "tag":"inf:oem_id_toshiba1", "desc":"Oem Identifier: Possibly Toshiba"},
    {"re":"MANM(JS)?", "tag":"inf:oem_id_unknown5", "desc":"Oem Identifier: unknown"},
    {"re":"MATB(JS)?", "tag":"inf:oem_id_toshiba2", "desc":"Oem Identifier: Possibly Toshiba"},
    {"re":"MALN(JS)?", "tag":"inf:oem_id_lenovo2", "desc":"Oem Identifier: Possibly Lenovo"},
    {"re":"MAFS(JS)?", "tag":"inf:oem_id_unknown6", "desc":"Oem Identifier: Unknown"},
    {"re":"MAMD(JS)?", "tag":"inf:oem_id_unknown7", "desc":"Oem Identifier: Unknown"},
    {"re":"MAMI(JS)?", "tag":"inf:oem_id_unknown8", "desc":"Oem Identifier: Unknown"},
    {"re":"MAGW(JS)?", "tag":"inf:oem_id_unknown9", "desc":"Oem Identifier: Unknown"},
    {"re":"MAEM(JS)?", "tag":"inf:oem_id_unknown10", "desc":"Oem Identifier: Unknown"},
    {"re":"ASU2(JS)?", "tag":"inf:oem_id_asus1", "desc":"Oem Identifier: Possibly Asus"},
    {"re":"CPDTDF(JS)?", "tag":"inf:oem_id_compaq1", "desc":"Oem Identifier: Possibly Compaq"},
    {"re":"CMNTDF(JS)?", "tag":"inf:oem_id_compaq2", "desc":"Oem Identifier: Possibly Compaq"},
    {"re":"CMDTDF(JS)?", "tag":"inf:oem_id_compaq3", "desc":"Oem Identifier: Possibly Compaq"},
    {"re":"HPCMHP(JS)?", "tag":"inf:oem_id_hp1", "desc":"Oem Identifier: Possibly HP"},
    {"re":"HPNTDF(JS)?", "tag":"inf:oem_id_hp2", "desc":"Oem Identifier: Possibly HP"},
    {"re":"HPDTDF(JS)?", "tag":"inf:oem_id_hp3", "desc":"Oem Identifier: Possibly HP"},
    {"re":"\(compatible; MSIE 5\.01", "tag":"inf:msie_5.01", "desc":"Internet Explorer 5.01"},
    {"re":"\(compatible; MSIE 6\.0", "tag":"inf:msie_6", "desc":"Internet Explorer 6"},
    {"re":"\(compatible; MSIE 7\.0", "tag":"inf:msie_7", "desc":"Internet Explorer 7"},
    {"re":"\(compatible; MSIE 8\.0", "tag":"inf:msie_8", "desc":"Internet Explorer 8"},
    {"re":"\(compatible; MSIE 9\.0", "tag":"inf:msie_9", "desc":"Internet Explorer 9"},
    {"re":"\(compatible; MSIE 10\.0", "tag":"inf:msie_10", "desc":"Internet Explorer 10"},
    {"re":"rv:11\.0\) like Gecko", "tag":"inf:msie_11", "desc":"Internet Explorer 11"},
    {"re":"^Mozilla\/4\.0", "tag":"inf:mozilla_4", "desc":"Mozilla 4.0"},
    {"re":"^Mozilla\/5\.0", "tag":"inf:mozilla_5", "desc":"Mozilla 5.0"},
    {"re":" WOW64", "tag":"inf:wow64", "desc":"WOW64 String - 32 bit app on a 64 bit machine"},
    {"re":" x64", "tag":"inf:x64", "desc":"x64 String"},
    {"re":"Windows NT CE", "tag":"inf:windows_ce", "desc":"Windows CE Machine"},
    {"re":"Windows 95", "tag":"inf:windows_95", "desc":"Windows 95 Machine"},
    {"re":"Windows 98", "tag":"inf:windows_98", "desc":"Windows 98 Machine"},
    {"re":"Windows 98; Win9x 4\.90", "tag":"inf:windows_me", "desc":"Windows ME Machine"},  
    {"re":"Windows NT 4.0", "tag":"inf:windows_nt_4", "desc":"Windows NT 4 Machine"},
    {"re":"Windows NT 5.0", "tag":"inf:windows_2000", "desc":"Windows 2000 Machine"},
    {"re":"Windows NT 5.01", "tag":"inf:windows_2000_sp1", "desc":"Windows 2000 SP1 Machine"},
    {"re":"Windows NT 5.1", "tag":"inf:windows_xp", "desc":"Windows XP Machine"},
    {"re":"Windows NT 5.2", "tag":"inf:windows_2003_xpx64", "desc":"Windows 2003 or XP x64 Machine"},
    {"re":"Windows NT 6.0", "tag":"inf:windows_vista", "desc":"Windows Vista Machine"},
    {"re":"Windows NT 6.1", "tag":"inf:windows_7", "desc":"Windows 7 Machine"},
    {"re":"Windows NT 6.2", "tag":"inf:windows_8", "desc":"Windows 8 Machine"},
    {"re":"Windows NT 6.3", "tag":"inf:windows_8.1", "desc":"Windows 8.1 Machine"},
    {"re":"Firefox\/\d", "tag":"inf:firefox", "desc":"Firefox Token"},
    {"re":"Chrome\/\d\d\.\d\.\d\d\d\d\.\d\d?\d?", "tag":"inf:chrome", "desc":"Chrome Token Included"},
    {"re":"Safari\/\d\d\d\.\d\d(\.\d\d)?", "tag":"inf:safari", "desc":"Safari Token Included"},
    {"re":"OPR\/\d\d\.\d\.\d{4}\.\d\d", "tag":"inf:new_opera", "desc":"Opera Token Included"},
    {"re":"Trident\/4\.0", "tag":"inf:trident_4_ie8", "desc":"Trident 4.0 used with IE8"},
    {"re":"Trident\/5\.0", "tag":"inf:trident_5_ie9", "desc":"Trident 5.0 used with IE9"},  
    {"re":"Trident\/6\.0", "tag":"inf:trident_6_ie10", "desc":"Trident 6.0 used with IE10"},    
    {"re":"Trident\/7\.0", "tag":"inf:trident_7_ie11", "desc":"Trident 7.0 used with IE11"},
    {"re":"\.NET CLR", "tag":"inf:dot_net", "desc":".NET Token present"},
    {"re":"chromeframe\/\d\d\.\d\.\d{4}\.\d\d\d;", "tag":"inf:chromeframe", "desc":"chromeframe token exists in UA String"},
    {"re":"Mozilla\/\d\.\d\+\(", "tag":"inv:spaces_replaced_with_plus", "desc":"It appears spaces are replaced with plus here, and hence not useful"},
    {"re":"Trident\/\d\.\d.*?Trident\/\d\.\d", "tag":"inv:multiple_trident", "desc":"The Trident string appears more than once"},
    {"re":"Trident\/\d\.\d.*?WOW64", "tag":"inv:trident_before_wow64", "desc":"The Trident token should be after the WOW64 token"},
    {"re":"Mozilla\/\d\.\d.*?Mozilla\/\d\.\d", "tag":"inv:multiple_mozilla", "desc":"The Mozilla Token should not appear more than once"},
    {"re":"\([^\)]+$", "tag":"inv:no_closing_paren", "desc":"An open paren exists with no closing paren"},
    {"re":"[A-Z]", "neg":1, "tag":"inv:all_lower", "desc":"There doesn't appear to be any capital letters, this is a concern"}
    ]



# If enable Commonality is enabled, it makes the connection for use for checking UAs
if enableCommonality == 1:
    import pymongo
    mongoserver = '%urmongo%'
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
    testuas = ['Mozilla/5.0 (X11; CrOS i686 4319.96.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.74 Safari/537.36']

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
            prettyPrint(ua, '2014-02-15', tags)         

#################################################################################
# prettyPrint(ua, day, tags)
# Takes a Useragent, day and tags and makes pretty output for the masses


def prettyPrint(ua, day, tags):
    infHead = 0
    invHead = 0
    print "\n--------------------\nUserAgent: %s\n" % ua
    common = howCommon(ua, day)
    #common = {'status':'Not Found'}
    if common['status'] == "Found":
        print "\tUser Agent Commonality: Found in DB for %s" % day
        print "\tNumber of Logons with UA: %s - Percentage of Total Logins for Day %s" % (common['total_logins'], common['total_logins_perc'])
        print "\tNumber of Login IDs with UA: %s - Percentage of Total Login IDs for Day %s" % (common['total_loginids'], common['total_loginids_perc'])
        print "\tNumber of Computers with UA: %s - Percentage of Total Computers for Day %s" % (common['total_computers'], common['total_computers_perc'])
        print "\tNumber of IPs with UA: %s - Percentage of Total IPs for Day %s" % (common['total_ips'], common['total_ips_perc'])
        print "\n"
    else:
        print "\tUser Agent Commonality: Not Found in DB for %s" % day
        print "\n"

    for t in tags:
        if t.find('inf:') == 0:
            if infHead == 0:
                infHead = 1
                print "\tInformational Components:"
            print "\t\tTag: %s - %s" % (t, retDescbyTag(t))
    for t in tags:
        if t.find('inv:') == 0:
            if invHead == 0:
                invHead = 1
                print "\n\tInvalid Components:"
            print "\t\tTag: %s - %s" % (t, retDescbyTag(t)) 





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
