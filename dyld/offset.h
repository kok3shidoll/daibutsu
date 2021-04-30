
void offset_init(void){
#if defined(N42_12H321)
    exportTableOffset = 0x13A3092D;
    MISValidateSignature = 0x30082cc8;
    MOV_R0_0__BX_LR = 0x3008153e;
    isIOS9 = 0;
#elif defined(N94_12H321)
    exportTableOffset = 0x137F3E85;
    MISValidateSignature = 0x2fe47ca0;
    MOV_R0_0__BX_LR = 0x2fe46516;
    isIOS9 = 0;
#elif defined(N78_12H321)
    exportTableOffset = 0x136AC9BD;
    MISValidateSignature = 0x2fd11ca0;
    MOV_R0_0__BX_LR = 0x2fd10516;
    isIOS9 = 0;
#elif defined(N42_13A452)
    exportTableOffset = 0x177207AD;
    MISValidateSignature = 0x33533ec8;
    MOV_R0_0__BX_LR = 0x3353243e;
    isIOS9 = 1;
#else
    exportTableOffset = 0xXXXXXXXX;
    MISValidateSignature = 0xXXXXXXXX;
    MOV_R0_0__BX_LR = 0xXXXXXXXX;
    isIOS9 = 0;
#endif
}
