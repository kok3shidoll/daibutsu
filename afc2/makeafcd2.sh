#!/bin/sh
sudo rm BUILD_AFC2/usr/share/daibutsuAFC2/libexec/afcd2
sudo rm BUILD_AFC2/etc/rc.d/afc2d_exec

gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.1.sdk -arch armv7 afcd2.c -o afcd2 -framework IOKit -framework CoreFoundation

strip afcd2
ldid -S afcd2
sudo cp -a afcd2 BUILD_AFC2/usr/share/daibutsuAFC2/libexec/afcd2
sudo chown 0:0 BUILD_AFC2/usr/share/daibutsuAFC2/libexec/afcd2
sudo ln -s /usr/share/daibutsuAFC2/libexec/afcd2 BUILD_AFC2/etc/rc.d/afc2d_exec

exit
