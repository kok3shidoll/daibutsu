# daibutsu
8.4.1 untether (for 32-bit iOS)  

## exploit
- A dyld exploit that overrides the MISValidateSignature in libmis.dylib (CVE-2015-7079)  
- OSUnserialize kernel Infoleak(CVE-2016-4655)  
- pegasus kernel exploit (CVE-2016-4656)  

### dyld
Change dyld_shared_cache and overrides _MISValidateSignature in libmis.dylib always return 0 to bypass code signing.  
(source code is still only for iPhone5,2-12H321)  

### helper
For loading substrate.  

### untether
old-style jailbreak untether (for iPhone5,2-12H321).  


[init] 2021/04/07  by dora2ios  
