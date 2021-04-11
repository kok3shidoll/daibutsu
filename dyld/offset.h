
void offset_init(void){
#if defined(N42_12H321)
    exportTableOffset = 0x13A3092D;
    MISValidateSignature = 0x30082cc8;
    MOV_R0_0__BX_LR = 0x3008153e;
#elif defined(N94_12H321)
    exportTableOffset = 0x137F3E85;
    MISValidateSignature = 0x2fe47ca0;
    MOV_R0_0__BX_LR = 0x2fe46516;
#else
    exportTableOffset = 0xXXXXXXXX;
    MISValidateSignature = 0xXXXXXXXX;
    MOV_R0_0__BX_LR = 0xXXXXXXXX;
#endif
}
