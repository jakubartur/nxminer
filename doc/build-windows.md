## Build Nxminer for Windows on Unix

This guide compiles Nxminer for windows on Unix. Building natively on Windows is not advised. It is incredibly difficult and not worth the trouble.

### Installing dependencies

Note: build-essential is installed because GCC is needed to build the depends

```
sudo apt-get install g++-mingw-w64-x86-64 mingw-w64-x86-64-dev autoconf automake libtool pkg-config build-essential ruby-full

cd depends

make HOST=x86_64-w64-mingw32 -j`nproc`

cd..
```

### Building

```
./autogen.sh

CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/ --disable-shared --enable-static-build  

make -j`nproc`
```
