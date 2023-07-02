#include <stdlib.h>

//https://github.com/qyang-nj/llios/blob/main/exported_symbol/README.md

void findInExportTable(uint8_t *exportStart, uint8_t *nodePtr, char *prevString, uint16_t* mdao);

//from https://github.com/bolderflight/uleb128

int DecodeUleb128(uint8_t *data, uint64_t *val);
int EncodeUleb128(uint64_t val, uint8_t *data);