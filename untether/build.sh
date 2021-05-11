#!/bin/sh
rm -r .DS_Store
rm -r */.DS_Store
rm -r */*/.DS_Store
rm -r */*/*/.DS_Store
rm -r */*/*/*/.DS_Store
rm -r */*/*/*/*/.DS_Store
rm -r */*/*/*/*/*/.DS_Store

dpkg-deb --build -Zgzip BUILD package/
