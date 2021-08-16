#!/bin/sh
sudo rm BUILD_AFC2/usr/share/daibutsuAFC2/afcd2

gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.1.sdk -arch armv7 afcd2.c -o afcd2 -framework IOKit -framework CoreFoundation

strip afcd2
ldid -S afcd2
sudo cp -a afcd2 BUILD_AFC2/usr/share/daibutsuAFC2/afcd2
sudo chown 0:0 BUILD_AFC2/usr/share/daibutsuAFC2/afcd2
