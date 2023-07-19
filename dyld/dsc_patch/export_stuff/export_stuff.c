#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "util.h"

#include "export_stuff.h"

int DecodeUleb128(uint8_t *data, uint64_t *val)
{
    /* Null pointer check */
    if ((!data) || (!val))
    {
        return 0;
    }
    uint64_t res = 0, shift = 0;
    uint16_t i = 0;
    while (1)
    {
        uint8_t b = data[i++];
        res |= (b & 0x7F) << shift;
        if (!(b & 0x80))
        {
            break;
        }
        shift += 7;
    }
    *val = res;
    return i;
}

int EncodeUleb128(uint64_t val, uint8_t *data)
{
    if (!data)
    {
        return 0;
    }
    uint16_t i = 0;
    do
    {
        uint8_t b = val & 0x7F;
        val >>= 7;
        if (val != 0)
        {
            b |= 0x80;
        }
        data[i++] = b;
    } while (val != 0);
    return i;
}

void findInExportTable(uint8_t *exportStart, uint8_t *nodePtr, char *prevString, uint16_t *mdao)
{
    uint64_t terminalSize;
    int byteCount = DecodeUleb128(nodePtr, &terminalSize);

    if (terminalSize != 0 && strcmp(prevString, "_MISValidateSignature") == 0)
    {
        uint64_t res;
        DecodeUleb128(nodePtr + byteCount + 1, &res);
        uint16_t mvsdataaddressoffset = nodePtr - exportStart + byteCount + 1;
        printf("mvsdataaddressoffset: %llx\n", res);
        *mdao = mvsdataaddressoffset;
    }

    uint8_t *childrenCountPtr = nodePtr + byteCount + terminalSize;
    uint8_t children_count = *childrenCountPtr;
    uint8_t *string = childrenCountPtr + 1;
    for (int i = 0; i < children_count; ++i)
    {
        char currString[4000];
        strcpy(currString, prevString);
        strcat(currString, (char *)string);
        string += strlen((char *)string) + 1;
        uint64_t child_offset;
        byteCount = DecodeUleb128(string, &child_offset);
        string += byteCount; // now s points to the next child's edge string
        findInExportTable(exportStart, exportStart + child_offset, currString, mdao);
    }
}