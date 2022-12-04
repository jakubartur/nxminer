## Build Nxminer on Unix

This guide is for building on Ubuntu. Building on Debian, Centos, or another flavour will follow the same general steps but package names may differ.

### Installing dependencies

Run the following to install the base dependencies

```
sudo apt-get install autoconf automake libtool pkg-config build-essential ruby-full

cd depends

make HOST=x86_64-pc-linux-gnu -j`nproc`

cd..
```

### Building

Run the following commands in the source to build the miner

```
./autogen.sh  

CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure --prefix=/ --disable-shared --enable-static-build

make -j`nproc`

strip nxminer
```  

No installation is necessary. You may run nxminer from the build directory directly, but you may do make install if you wish to install nxminer to a system location or location you specified.
