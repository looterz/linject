Lightweight Injection Tool
=======================

A lightweight command-line DLL injection and ejection tool.

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

Pull requests are welcome. Especially when it comes to multi-platform support, as some of the code is currently using VirtualAllocEx, and probably other issues I don't even know about.

Credits
-------

Most of the injection code originates from methods and practices developed by Zoltan Csizmadias, Felix Kasza and mcMike.