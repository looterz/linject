Lightweight Injection Tool
=======================

Command-line DLL Injection and Ejection.

Usage
-----

Inject DLL Into Process
```
linject inject -process proc.exe -dll .\payload.dll
```

Eject DLL From Process
```
linject eject -process proc.exe -dll .\payload.dll
```
Dump Modules in use by Process
```
linject dump -process proc.exe
```

Building
--------

linject requires [Bootil](https://github.com/garrynewman/bootil). Simply build Bootil in release configuration, and place bootil_static.lib into lib/ and the Bootil folder containing the headers into include/

linject uses [premake](http://industriousone.com/premake) to build project files, simply place premake4 into the build folder and run build.bat

Contributing
------------

Pull requests are welcome. Especially when it comes to multi-platform support, as some of the code is currently using VirtualAllocEx.

Credits
-------

Most of the injection code originates from methods and practices developed by Zoltan Csizmadias, Felix Kasza and mcMike.