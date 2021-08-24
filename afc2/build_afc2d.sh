#!/bin/sh
sudo rm -r .DS_Store
sudo rm -r */.DS_Store
sudo rm -r */*/.DS_Store
sudo rm -r */*/*/.DS_Store
sudo rm -r */*/*/*/.DS_Store
sudo rm -r */*/*/*/*/.DS_Store
sudo rm -r */*/*/*/*/*/.DS_Store

dpkg-deb --build -Zgzip BUILD_AFC2 package/
