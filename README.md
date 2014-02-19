IronUA
======

Rules Based setup for User Agents to determine Intel Context

Some basic usage:

- To use by itself, copy a list of Useragents into "TestUAs" and just run it. 
- To use it a module in your script

Put it in the same directory as your script
add:

import ironua 

Then for example:

for useragent in useragents:

  tags = []
  
  #Get the Tags for your UA
  
  tags = ironua.tagUserAgent(useragent)
  
  #Get the commonality (if enabled in your system and if you have the proper backend)
  
  day = '2014-02-18' # The day you want to determine commonality on 
  
  common = ironua.howCommon(useragent, day)
  
  #You can then use this info in your script. 
  
  # There is also a prettyPrint option (you still need to run the tags manually
  
  # You do not need to run the howCommon function.  
  
  ironua.prettyPrint(useragent, day, tags)
  
  
  More info to come on the commonality DB Schema and how to create that. 
  
  
  
