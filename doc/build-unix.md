## Build Nxminer on Unix

This guide is for building on Ubuntu. Building on Debian, Centos, or another flavour will follow the same general steps but package names may differ.

### Installing dependencies

Run the following to install the base dependencies

```
sudo apt-get install build-essential autoconf automake libtool pkg-config libssl-dev libcurl4-openssl-dev libncurses5-dev
```

### Building

Run the following commands in the source to build the miner

`./autogen.sh`  
`CFLAGS="-O2 -Wall -march=native" ./configure`  
`make`  

No installation is necessary. You may run nxminer from the build directory directly, but you may do make install if you wish to install nxminer to a system location or location you specified.
