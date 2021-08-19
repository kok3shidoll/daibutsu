#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFSerialize.h>
#include <CoreFoundation/CoreFoundation.h>
#include <assert.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/mount.h>
#include <sys/stat.h>

// daibutsu AFC2 (original by TaiG AFC2)
// based on attach.c by danzatt

int copy_dmg(char *outfile, char *in){
    size_t sz;
    char *buf;
    
    FILE *fd = fopen(in, "r");
    if (!fd) {
        printf("error opening %s\n", in);
        return -1;
    }
    
    FILE *out = fopen(outfile, "w");
    if (!out) {
        printf("error opening %s\n", outfile);
        return -1;
    }
    
    fseek(fd, 0, SEEK_END);
    sz = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    buf = malloc(sz);
    if (!buf) {
        printf("error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    fread(buf, sz, 1, fd);
    fclose(fd);
    
    fwrite(buf, sz, 1, out);
    fflush(out);
    fclose(out);
    
    free(buf);
    
    return 0;
}

int main(int argc, char **argv) {

    char *dmgpath = "/usr/share/daibutsuAFC2/afc2d.dmg";
    
    FILE *fd = fopen(dmgpath, "r");
    if (!fd) {
        printf("error opening %s\n", dmgpath);
        return -1;
    }
    
    char zeroBuf[0x81];
    memset(&zeroBuf, 0x00, 0x81);
    memset(&zeroBuf, 0x30, 0x80);
    mkdir("/private/var/run", 0x1ed);
    mkdir("/private/var/run/lockdown_patch", 0x1ed);
    
    char str[512];
    memset(&str, 0x0, 512);
    sprintf(str, "/private/var/run/lockdown_patch/%s", zeroBuf);
    mkdir(str, 0x1ed);
    memset(&str, 0x0, 512);
    sprintf(str, "/private/var/run/lockdown_patch/%s/%s", zeroBuf, zeroBuf);
    mkdir(str, 0x1ed);
    memset(&str, 0x0, 512);
    sprintf(str, "/private/var/run/lockdown_patch/%s/%s/lockdown_patch.dmg", zeroBuf, zeroBuf);
    
    int r;
    r = copy_dmg(str, dmgpath);
    
    usleep(10000);
    
    if(r == 0){
        
        mkdir("/DeveloperPatch", 0x1ed);
        
        io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOHDIXController"));
        assert(service);
        io_connect_t connect;
        assert(!IOServiceOpen(service, mach_task_self(), 0, &connect));
        
        CFStringRef uuid = CFUUIDCreateString(NULL, CFUUIDCreate(NULL));
        CFMutableDictionaryRef props = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(props, CFSTR("hdik-unique-identifier"), uuid);
        CFDataRef path = CFDataCreateWithBytesNoCopy(NULL, (UInt8 *) str, strlen(str), kCFAllocatorNull);
        assert(path);
        CFDictionarySetValue(props, CFSTR("image-path"), path);
        CFDataRef props_data = IOCFSerialize(props, 0);
        assert(props_data);
        
        struct HDIImageCreateBlock64 {
            uint32_t magic;
            uint32_t one;
            char *props;
            uint32_t null;
            uint32_t props_size;
            char ignored[0xf8 - 16];
        } stru;
        memset(&stru, 0, sizeof(stru));
        stru.magic = 0xbeeffeed;
        stru.one = 1;
        stru.props = (char *) CFDataGetBytePtr(props_data);
        stru.props_size = CFDataGetLength(props_data);
        
        uint32_t val;
        size_t val_size = sizeof(val);
        
        kern_return_t ret = IOConnectCallStructMethod(connect, 5, &stru, 0x100, &val, &val_size);
        if(ret) {
            fprintf(stderr, "returned %x\n", ret);
            return 1;
        }
        assert(val_size == sizeof(val));
        
        CFMutableDictionaryRef pmatch = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(pmatch, CFSTR("hdik-unique-identifier"), uuid);
        CFMutableDictionaryRef matching = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(matching, CFSTR("IOPropertyMatch"), pmatch);
        service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
        if(!service) {
            fprintf(stderr, "successfully attached, but didn't find top entry in IO registry\n");
            return 1;
        }
        
        bool ok = false;
        io_iterator_t iter;
        assert(!IORegistryEntryCreateIterator(service, kIOServicePlane, kIORegistryIterateRecursively, &iter));
        while( (service = IOIteratorNext(iter)) ) {
            CFStringRef bsd_name = IORegistryEntryCreateCFProperty(service, CFSTR("BSD Name"), NULL, 0);
            if(bsd_name) {
                char buf[MAXPATHLEN-8];
                assert(CFStringGetCString(bsd_name, buf, sizeof(buf), kCFStringEncodingUTF8));
                char stderr[MAXPATHLEN];
                //puts(buf);
                sprintf(stderr, "/dev/%s", buf);
                char* nmr = strdup(stderr);
                int mntr = mount("hfs", "/DeveloperPatch", MNT_RDONLY, &nmr);
                if(mntr == 0) ok = true;
            }
        }
        
        if(!ok) {
            fprintf(stderr, "successfully attached, but didn't find BSD name in IO registry\n");
            return 1;
        }
    }
    
    return 0;
}
