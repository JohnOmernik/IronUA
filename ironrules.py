

#Rules Broken out into separate Python file with Changelog and Version Number


rulver = "2014020v1"

 
# Tag based rules. Rules are in "Python" syntax, basically looking for the presence or lack of presence of tags in the tags collection, and if that condition is met, add a tag.
tagrules = [
# Invalid Browser Representations
    {"rule":"'inf:new_opera' in tags and not ('inf:valid_safari' in tags or 'inf:valid_chrome' in tags or 'inf:valid_new_opera' in tags)", "tag":"inv:new_opera", "desc":"New Opera Token string but does not include valid Safari, Chrome, or Opera string"},
    {"rule":"'inf:chrome' in tags and not ('inf:valid_safari' in tags or 'inf:valid_chrome' in tags or 'inf:valid_new_opera' in tags)", "tag":"inv:chrome", "desc":"Chrome Token string but does not include valid Safari, Chrome, or Opera string"},
    {"rule":"'inf:safari' in tags and not ('inf:valid_safari' in tags or 'inf:valid_chrome' in tags or 'inf:valid_new_opera' in tags)", "tag":"inv:safari", "desc":"Safari Token string but does not include valid Safari, Chrome, or Opera string"},
    {"rule":"'inf:mobile_safari' in tags and not ('inf:valid_mobile_safari' in tags or 'inf:valid_ios_chrome' in tags)", "tag":"inv:mobile_safari", "desc":"Mobile Safari Token string but does not include valid Mobile Safari UA"},
    {"rule":"'inf:chrome_ios' in tags and not ('inf:valid_ios_chrome' in tags)", "tag":"inv:chrome_ios", "desc":"IOS Chrome string but does not include valid IoS Chrome UA"},
    {"rule":"not 'inf:valid_firefox' in tags and 'inf:firefox' in tags", "tag":"inv:filefox", "desc":"Firefox token in string but does not include valid firefox string"},
    {"rule":"'inf:msie' in tags and not ('inf:msie_5.01' in tags or 'inf:msie_5.5' in tags or 'inf:msie_6' in tags or 'inf:msie_7' in tags or 'inf:msie_8' in tags or 'inf:msie_9' in tags or 'inf:msie_10' in tags)", "tag":"inv:msie_version", "desc":"Invalid Version of MSIE Represented in MSIE Token"},
# Invalid Mozilla Version to MSIE Version
    {"rule":"'inf:mozilla_5' in tags and ('inf:msie_5.01' in tags or 'inf:msie_6' in tags or 'inf:msie_7' in tags or 'inf:msie_8' in tags)", "tag":"inv:mozilla_5_w_old_msie", "desc":"Mozilla/5.0 with IE Version less then MSIE 9"},
# Invalid Media Center to OS Representations
    {"rule":"'inf:media_center_6_0' in tags and not 'inf:windows_7' in tags", "tag":"inv:media_center_6_0", "desc":"Invalid Media Center 6.0 without Windows 7"},
    {"rule":"'inf:media_center_5_0' in tags and not 'inf:windows_vista' in tags", "tag":"inv:media_center_5_0", "desc":"Invalid Media Center 5.0 without Windows Vista"},
    {"rule":"('inf:media_center_4_0' in tags or 'inf:media_center_3_1' in tags or 'inf:media_center_3_0' in tags or 'inf:media_center_2_8' in tags or 'inf:media_center_2_7' in tags) and not 'inf:windows_xp' in tags", "tag":"inv:media_center_xp_no_xp", "desc":"Invalid Media Center 4.0 or lower without Windows XP"}
]

# UA rules are regex based, if the regex matches, it appends the tag. 
# Also, if the key neg exists, than it appends the tag if the reg DOESN'T match.
# Try to keep these simple if possible, but sometimes complexity is needed
 
uarules = [
# Some Invalid Things
    {"re":"(mozilla|windows nt|msie|firefox|chrome\/|safari)", "tag":"inv:improper_case", "desc":"Tokens identified with improper casing"},
    {"re":"Windows XP", "tag":"inv:windowsxp", "desc":"Windows XP String identified"},
    {"re":"\s{2,}", "tag":"inv:extra_spaces", "desc":"Extra spaces in UA make make matching very difficult"},
    {"re":"^Mozilla\/\d\.\d ", "neg":1, "tag":"inv:no_mozilla", "desc":"Doesn't start with Mozilla"},
    {"re":"Mozilla\/\d\.\d\+\(", "tag":"inv:spaces_replaced_with_plus", "desc":"It appears spaces are replaced with plus here, and hence not useful"},
    {"re":"Trident\/\d\.\d.*?Trident\/\d\.\d", "tag":"inv:multiple_trident", "desc":"The Trident string appears more than once"},
    {"re":"Trident\/\d\.\d.*?WOW64", "tag":"inv:trident_before_wow64", "desc":"The Trident token should be after the WOW64 token"},
    {"re":"Mozilla\/\d\.\d.*?Mozilla\/\d\.\d", "tag":"inv:multiple_mozilla", "desc":"The Mozilla Token should not appear more than once"},
    {"re":"\([^\)]+$", "tag":"inv:no_closing_paren", "desc":"An open paren exists with no closing paren"},
    {"re":"\(compatible;.*[^\)]$", "tag":"inv:no_compatible_no_end_paren", "desc":"Another look for missing parens"},
    {"re":"[A-Z]", "neg":1, "tag":"inv:all_lower", "desc":"There doesn't appear to be any capital letters, this is a concern"},
# Valid full UA Strings
    {"re":"^Mozilla\/5\.0 \((X11; CrOS i686 \d{4}\.\d{2}(\.\d{1,2})?|Windows NT \d.\d(; WOW64)?|Macintosh; Intel Mac OS X \d\d_\d(_\d)?)\) AppleWebKit\/\d{3}\.\d\d \(KHTML, like Gecko\) Chrome\/\d\d\.\d\.\d\d\d\d\.\d\d?\d? Safari\/\d\d\d\.\d\d$", "tag":"inf:valid_chrome", "desc":"Valid Google Chrome UA"},
    {"re":"^Mozilla\/5\.0 \((Windows NT \d.\d(; WOW64)?|Macintosh; Intel Mac OS X \d\d_\d(_\d)?)\) AppleWebKit\/\d{3}\.\d\d(\.\d{1,2})? \(KHTML, like Gecko\) Version\/\d\.\d\.\d Safari\/\d\d\d\.\d\d(\.\d{1,2})?$", "tag":"inf:valid_safari", "desc":"Valid Safari UA"},
    {"re":"^Mozilla/5.0 \(iP(od|ad|hone); CPU OS \d_\d_\d like Mac OS X\) AppleWebKit\/\d{3}\.\d\d(\.\d{1,2})? \(KHTML, like Gecko\) CriOS\/\d\d\.\d\d?\.\d{4}\.\d{2,3} Mobile\/[^ ]+ Safari\/\d{4}\.\d{1,2}$", "tag":"inf:valid_ios_chrome", "desc":"Valid iOS Chrome UA"},
    {"re":"^Mozilla/5.0 \(iP(od|ad|hone); CPU( iPhone)? OS \d_\d_\d like Mac OS X\) AppleWebKit\/\d{3}\.\d\d(\.\d{1,2})? \(KHTML, like Gecko\) Version\/\d\.\d Mobile\/[^ ]+ Safari\/\d{4}\.\d{1,2}(\.\d)?$", "tag":"inf:valid_mobile_safari", "desc":"Valid Mobile Safari UA"},
    {"re":"^Mozilla\/5\.0 \((Windows NT \d.\d;( WOW64;)?|Macintosh; Intel Mac OS X \d\d\.\d;) rv:\d\d\.\d\) Gecko\/\d{8} Firefox\/\d\d\.\d", "tag":"inf:valid_firefox", "desc":"This appears to be a valid Firefox UA"},
    {"re":"^Mozilla\/5\.0 \(Windows NT \d\.\d;?( WOW64)?\) AppleWebKit\/\d{3}\.\d\d \(KHTML, like Gecko\) Chrome\/\d\d\.\d\.\d\d\d\d\.\d\d\d? Safari\/\d\d\d\.\d\d OPR\/\d\d\.\d\.\d{4}\.\d\d$", "tag":"inf:valid_new_opera", "desc":"Valid New Style Opera UA"},
# Tokens - not bad, just good to know all inf
###### Apple and IOS
    {"re":"\(iPad; ", "tag":"inf:ipad", "desc":"iPad Token"},
    {"re":"\(iPod; ", "tag":"inf:ipod", "desc":"iPod Token"},
    {"re":"\(iPhone; ", "tag":"inf:iphone", "desc":"iPhone Token"},
    {"re":"Macintosh; Intel Mac OS X \d\d", "tag":"inf:mac", "desc":"Apple Computer"},
###### Chrome OS
    {"re":" CrOS ", "tag":"inf:chrome_os", "desc":"CrOS - Chrome OS Token"},
###### Internet Explorer
    {"re":" MSIE \d\d?\.\d\d?", "tag":"inf:msie", "desc":"MSIE Token exists"},
    {"re":"\(compatible; MSIE 5\.01;", "tag":"inf:msie_5.01", "desc":"Internet Explorer 5.01"},
    {"re":"\(compatible; MSIE 5\.5;", "tag":"inf:msie_5.5", "desc":"Internet Explorer 5.5"},
    {"re":"\(compatible; MSIE 6\.0;", "tag":"inf:msie_6", "desc":"Internet Explorer 6"},
    {"re":"\(compatible; MSIE 7\.0;", "tag":"inf:msie_7", "desc":"Internet Explorer 7"},
    {"re":"\(compatible; MSIE 8\.0;", "tag":"inf:msie_8", "desc":"Internet Explorer 8"},
    {"re":"\(compatible; MSIE 9\.0;", "tag":"inf:msie_9", "desc":"Internet Explorer 9"},
    {"re":"\(compatible; MSIE 10\.0;", "tag":"inf:msie_10", "desc":"Internet Explorer 10"},
    {"re":"rv:11\.0\) like Gecko", "tag":"inf:msie_11", "desc":"Internet Explorer 11"},
######  Mozilla Version
    {"re":"^Mozilla\/4\.0", "tag":"inf:mozilla_4", "desc":"Mozilla 4.0"},
    {"re":"^Mozilla\/5\.0", "tag":"inf:mozilla_5", "desc":"Mozilla 5.0"},
###### CPU Arch
    {"re":" WOW64", "tag":"inf:wow64", "desc":"WOW64 String - 32 bit app on a 64 bit machine"},
    {"re":" x64", "tag":"inf:x64", "desc":"x64 String"},
###### Windows Versions
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
###### Browser Tokens
    {"re":"Firefox\/\d", "tag":"inf:firefox", "desc":"Firefox Token"},
    {"re":"Chrome\/\d\d\.\d\.\d\d\d\d\.\d\d?\d?", "tag":"inf:chrome", "desc":"Chrome Token Included"},
    {"re":"Safari\/\d\d\d\.\d\d(\.\d\d)?", "tag":"inf:safari", "desc":"Safari Token Included"},
    {"re":"OPR\/\d\d\.\d\.\d{4}\.\d\d", "tag":"inf:new_opera", "desc":"Opera Token Included"},
    {"re":"Mobile\/[^ ]+ Safari\/\d{4}\.\d{1,2}(\.\d)?", "tag":"inf:mobile_safari", "desc":"Mobile Safari Token"},
    {"re":"Maxthon\/\d\.\d\.\d\.\d{3}", "tag":"inf:maxthon", "desc":"Maxthon Cloud Browser Tag"},
    {"re":" CriOS\/\d\d\.\d\d?\.\d{4}\.\d{2,3} ", "tag":"inf:chrome_ios", "desc":"Chrome for iOS Token"},
###### Trident Rendering Engine Tokens
    {"re":"Trident\/4\.0", "tag":"inf:trident_4_ie8", "desc":"Trident 4.0 used with IE8"},
    {"re":"Trident\/5\.0", "tag":"inf:trident_5_ie9", "desc":"Trident 5.0 used with IE9"}, 
    {"re":"Trident\/6\.0", "tag":"inf:trident_6_ie10", "desc":"Trident 6.0 used with IE10"},   
    {"re":"Trident\/7\.0", "tag":"inf:trident_7_ie11", "desc":"Trident 7.0 used with IE11"},
###### Misc Informational Tokens
    {"re":" LG-VS410PP Build\/", "tag":"inf:lg_vs410pp", "desc":"LG Optimus Zone VS412PP Tablet Token"},
    {"re":"Linux; U; Android", "tag":"inf:android", "desc":"Android OS Token"},
    {"re":"\.NET CLR", "tag":"inf:dot_net", "desc":".NET Token present"},
    {"re":"chromeframe\/\d\d\.\d\.\d{4}\.\d\d\d;", "tag":"inf:chromeframe", "desc":"chromeframe token exists in UA String"},
    {"re":"MRA \d\.\d \(build \d{4}\)", "tag":"inf:mail_ru_agent", "desc":"Mail.ru User Agent"},
    {"re":"GTB\d\.\d", "tag":"inf:google_tool_bar", "desc":"Google Tool Bar Token"},
###### Windows Media Center Tokens
    {"re":"Media Center PC 2\.7", "tag":"inf:media_center_2_7", "desc":"Windows Media Center 2.7 Windows XP 2002"},
    {"re":"Media Center PC 2\.8", "tag":"inf:media_center_2_8", "desc":"Windows Media Center 2.8 Windows XP 2004"},
    {"re":"Media Center PC 3\.0", "tag":"inf:media_center_3_0", "desc":"Windows Media Center 3.0 - Windows XP 2005 - W/SP2"},
    {"re":"Media Center PC 3\.1", "tag":"inf:media_center_3_1", "desc":"Windows Media Center Windows XP Update Rollup 1 2005"},
    {"re":"Media Center PC 4\.0", "tag":"inf:media_center_4_0", "desc":"Windows Media Center Windows XP Update Rollup 2 2005"},
    {"re":"Media Center PC 5\.0", "tag":"inf:media_center_5_0", "desc":"Windows Media Center 5.0 - Windows Vista"},
    {"re":"Media Center PC 5\.1", "tag":"inf:media_center_5_1", "desc":"Windows Media Center 5.1 - Media Center TV Pack"},
    {"re":"Media Center PC 6\.0", "tag":"inf:media_center_6_0", "desc":"Windows Media Center 6.0 - Windows 7"},
# Custom Mobile Apps
    {"re":"^SchwabMobile\/\d", "tag":"inf:schwabmobile", "desc":"Schwabmobile Apps"},
    {"re":"^SchwabMobileForAndroid\/\d", "tag":"inf:schwabmobile_android", "desc":"Schwabmobile For Android app"},
    {"re":"ScottradeMobileApplication \d\.\d(\.\d)?;", "tag":"inf:scotttrade_mobile_app", "desc":"Token for Scott trade mobile applications"},
# OEM Identifiers in Windows/MSIE
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
    {"re":"HPDTDF(JS)?", "tag":"inf:oem_id_hp3", "desc":"Oem Identifier: Possibly HP"}
    ]
