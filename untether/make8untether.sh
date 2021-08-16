#!/bin/sh
sudo rm BUILD/daibutsu

 gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS9.2.sdk -DUNTETHER -arch armv7 untether32.c patchfinder.c -o untether32 -framework IOKit -std=gnu99 -fno-stack-protector -Os -DIOS_VIII_UNTETHER

ldid -Sent.xml untether32
cp -a untether32 BUILD/daibutsu
sudo chown 0:0 BUILD/daibutsu
