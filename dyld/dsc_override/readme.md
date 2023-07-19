# haxx_override

## build
- armv7/armv7s
```
gcc haxx_override.c export_stuff/export_stuff.c -Iexport_stuff/ -o haxx_override
```

- arm64
```
gcc -DARM64 haxx_override.c export_stuff/export_stuff.c -Iexport_stuff/ -o haxx_override
```

## how to use
```
./haxx_override <path/to/dsc>
```

## note
ios 8 only.
The dsc specified in the argument is overwritten. please be sure to make backups in the test environment.
This code is still dirty. many error handles are not yet implemented.
please use ../dsc_patch and see if the same is generated.
