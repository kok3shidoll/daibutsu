# daibutsu
7.0-9.1 untether only (for 32/64 bit iOS)  
8.4.1 Jailbreak for 32 bits.

## 警告
日本国内において、及び日本国内向けに悪用することを禁じます。

## exploit
- A dyld exploit that overrides the MISValidateSignature in libmis.dylib (CVE-2015-7079)  
- OSUnserialize kernel Infoleak(CVE-2016-4655)  
- pegasus kernel exploit (CVE-2016-4656)  

### dyld
Change dyld_shared_cache and overrides _MISValidateSignature in libmis.dylib always return 0 to bypass code signing.  

#### build&&run
```
gcc (-DIOS8) (-DARM64) haxx.c export_stuff/export_stuff.c -Iexport_stuff/ -o haxx
./haxx dyld_shared_cache_[armv7s] dyld_shared_cache_[armv7s]_hack
```

- Arch  
  - A5&A5rA: `armv7`  
  - A6: `armv7s`  
  - A7/A8/A9: `arm64`

### helper
For loading substrate.  

### untether
old-style jailbreak untether.  

#### build
```
./make.sh
```

## How To Install Untether
### code signing bypass
- replace `/System/Library/Caches/com.apple.dyld/dyld_shared_cache_[armv7s]` on your device with the patched it.  

### automatically apply kernel patch at boot time (iOS 8)
- replace `/usr/libexec/CrashHousekeeping` with a symlink to `/untether32`.  
- change the launchdaemon startup order so that other daemons start after the kernel patch.  

*see `untether/install.txt`.  


[init] 2021/04/07  by dora2ios  
[update] 2021/04/10  by dora2ios  
[update] 2021/05/01  by dora2ios  
[update] 2022/06/23  by TheRealClarity  
