#!/bin/sh
sudo rm -r .DS_Store
sudo rm -r */.DS_Store
sudo rm -r */*/.DS_Store
sudo rm -r */*/*/.DS_Store
sudo rm -r */*/*/*/.DS_Store
sudo rm -r */*/*/*/*/.DS_Store
sudo rm -r */*/*/*/*/*/.DS_Store
sudo chown 0:0 BUILD/daibutsu
dpkg-deb --build -Zgzip BUILD package/
