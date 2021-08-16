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

int main(int argc, char **argv) {

    char *abspath = "/usr/share/daibutsuAFC2/afc2d.dmg";
    
    FILE *fd = fopen(abspath, "r");
    if (!fd) {
        printf("error opening!\n");
        return -1;
    }
    
    mkdir("/DeveloperPatch", 0x1ed);
    
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOHDIXController"));
    assert(service);
    io_connect_t connect;
    assert(!IOServiceOpen(service, mach_task_self(), 0, &connect));
    
    CFStringRef uuid = CFUUIDCreateString(NULL, CFUUIDCreate(NULL));
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(props, CFSTR("hdik-unique-identifier"), uuid);
    CFDataRef path = CFDataCreateWithBytesNoCopy(NULL, (UInt8 *) abspath, strlen(abspath), kCFAllocatorNull);
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
    return 0;
}
