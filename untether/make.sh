#!/bin/sh

 gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS9.2.sdk -DUNTETHER -arch armv7 untether32.c patchfinder.c -o untether32 -framework IOKit -std=gnu99 -fno-stack-protector

ldid -Sent.xml untether32
