# daibutsu
8.4.1 untether (for 32-bit iOS)  

## exploit
- A dyld exploit that overrides the MISValidateSignature in libmis.dylib (CVE-2015-7079)  
- OSUnserialize kernel Infoleak(CVE-2016-4655)  
- pegasus kernel exploit (CVE-2016-4656)  

### dyld
Change dyld_shared_cache and overrides _MISValidateSignature in libmis.dylib always return 0 to bypass code signing.  
(source code is still only for iPhone5,2-12H321)  

#### build&&run
```
gcc haxx.c -o haxx
./haxx dyld_shared_cache_armv7s dyld_shared_cache_armv7s_hack
```

### helper
For loading substrate.  

### untether
old-style jailbreak untether (for iPhone5,2-12H321).  

#### build
```
./make.sh
```

## How To Install Untether
### code signing bypass
- replace `/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s` on your device with the patched it.  

### automatically apply kernel patch at boot time
- replace `/usr/libexec/CrashHousekeeping` with a symlink to `/untether32`.  
- change the launchdaemon startup order so that other daemons start after the kernel patch.  

*see `untether/install.txt`.  


[init] 2021/04/07  by dora2ios  
[update] 2021/04/10  by dora2ios  
