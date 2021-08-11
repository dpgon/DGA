rule FluBot: FluBot 
{ 
meta: 
    description = "FluBot Core" 
    author = "Incibe" 
    version = "0.1" 
     
strings: 
 $s1 = "Bot.java" 
 $s2 = "BotId.java" 
 $s3 = "BrowserActivity.java" 
 $s4 = "BuildConfig.java" 
 $s5 = "DGA.java" 
 $s6 = "SocksClient.java" 
 $s7 = "SmsReceiver.java" 
 $s8 = "Spammer.java" 
  
condition: 
    all of them 
}  
