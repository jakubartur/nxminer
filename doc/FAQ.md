# Frequently Asked Questions

Q: nxminer segfaults when I change my shell window size.  
A: Older versions of libncurses have a bug to do with refreshing a window
after a size change. Upgrading to a new version of curses will fix it.

Q: Can I mine on servers from different networks (eg smartcoin and bitcoin) at
the same time?  
A: No, nxminer keeps a database of the block it's working on to ensure it does
not work on stale blocks, and having different blocks from two networks would
make it invalidate the work from each other.

Q: Can I change the intensity settings individually for each GPU?  
A: Yes, pass a list separated by commas such as -I d,4,9,9

Q: Can I put multiple pools in the config file?  
A: Yes, check the example.conf file. Alternatively, set up everything either on
the command line or via the menu after startup and choose settings->write
config file and the file will be loaded one each startup.

Q: The build fails with gcc is unable to build a binary.  
A: Remove the "-march=native" component of your CFLAGS as your version of gcc
does not support it.

Q: The CPU usage is high.  
A: The ATI drivers after 11.6 have a bug that makes them consume 100% of one
CPU core unnecessarily so downgrade to 11.6. Binding nxminer to one CPU core on
windows can minimise it to 100% (instead of more than one core). Driver version
11.11 on linux and 11.12 on windows appear to have fixed this issue. Note that
later drivers may have an apparent return of high CPU usage. Try
'export GPU_USE_SYNC_OBJECTS=1' on Linux before starting nxminer.

Q: Can you implement feature X?  
A: I can, but time is limited, and people who donate are more likely to get
their feature requests implemented.

Q: My GPU hangs and I have to reboot it to get it going again?  
A: The more aggressively the mining software uses your GPU, the less overclock
you will be able to run. You are more likely to hit your limits with nxminer
and you will find you may need to overclock your GPU less aggressively. The
software cannot be responsible and make your GPU hang directly. If you simply
cannot get it to ever stop hanging, try decreasing the intensity, and if even
that fails, try changing to the poclbm kernel with -k poclbm, though you will
sacrifice performance. nxminer is designed to try and safely restart GPUs as
much as possible, but NOT if that restart might actually crash the rest of the
GPUs mining, or even the machine. It tries to restart them with a separate
thread and if that separate thread dies, it gives up trying to restart any more
GPUs.

Q: Work keeps going to my backup pool even though my primary pool hasn't
failed?  
A: Nxminer checks for conditions where the primary pool is lagging and will
pass some work to the backup servers under those conditions. The reason for
doing this is to try its absolute best to keep the GPUs working on something
useful and not risk idle periods. You can disable this behaviour with the
option --failover-only.

Q: Is this a virus?  
A: Nxminer is being packaged with other trojan scripts and some antivirus
software is falsely accusing nxminer.exe as being the actual virus, rather
than whatever it is being packaged with. If you installed nxminer yourself,
then you do not have a virus on your computer. Complain to your antivirus
software company. They seem to be flagging even source code now from nxminer
as viruses, even though text source files can't do anything by themself.

Q: Can you modify the display to include more of one thing in the output and
less of another, or can you change the quiet mode or can you add yet another
output mode?  
A: Everyone will always have their own view of what's important to monitor.
The defaults are very sane and I have very little interest in changing this
any further.

Q: Can you change the autofan/autogpu to change speeds in a different manner?  
A: The defaults are sane and safe. I'm not interested in changing them
further. The starting fan speed is set to 50% in auto-fan mode as a safety
precaution.

Q: Why is my efficiency above/below 100%?  
A: Efficiency simply means how many shares you return for the amount of work
you request. It does not correlate with efficient use of your hardware, and is
a measure of a combination of hardware speed, block luck, pool design and other
factors

Q: What are the best parameters to pass for X pool/hardware/device.  
A: Virtually always, the DEFAULT parameters give the best results. Most user
defined settings lead to worse performance. The ONLY thing most users should
need to set is the Intensity.

Q: What happened to CPU mining?  
A: Being increasingly irrelevant for most users, and a maintenance issue, it is
no longer under active development and will not be supported unless someone
steps up to help maintain it. No binary builds supporting CPU mining will be
released but CPU mining can be built into nxminer when it is compiled.

Q: I upgraded nxminer version and my hashrate suddenly dropped!  
A: No, you upgraded your SDK version unwittingly between upgrades of nxminer
and that caused  your hashrate to drop. See the next question.

Q: I upgraded my ATI driver/SDK/nxminer and my hashrate suddenly dropped!  
A: The hashrate performance in nxminer is tied to the version of the ATI SDK
that is installed only for the very first time nxminer is run. This generates
binaries that are used by the GPU every time after that. Any upgrades to the
SDK after that time will have no effect on the binaries. However, if you
install a fresh version of nxminer, and have since upgraded your SDK, new
binaries will be built. It is known that the 2.6 ATI SDK has a huge hashrate
penalty on generating new binaries. It is recommended to not use this SDK at
this time unless you are using an ATI 7xxx card that needs it.

Q: Which ATI SDK is the best for nxminer?  
A: At the moment, versions 2.4 and 2.5 work the best. If you are forced to use
the 2.6 SDK, the phatk kernel will perform poorly, while the diablo or my
custom modified poclbm kernel are optimised for it.

Q: I have multiple SDKs installed, can I choose which one it uses?  
A: Run nxminer with the -n option and it will list all the platforms currently
installed. Then you can tell nxminer which platform to use with --gpu-platform.

Q: GUI version?  
A: No. The RPC interface makes it possible for someone else to write one
though.

Q: I'm having an issue. What debugging information should I provide?  
A: Start nxminer with your regular commands and add -D -T --verbose and provide
the full startup output and a summary of your hardware, operating system, ATI
driver version and ATI stream version.

Q: nxminer reports no devices or only one device on startup on Linux although
I have multiple devices and drivers+SDK installed properly?  
A: Try "export DISPLAY=:0" before running nxminer.

Q: My network gets slower and slower and then dies for a minute?  
A; Try the --net-delay option.

Q: How do I tune for p2pool?  
A: p2pool has very rapid expiration of work and new blocks, it is suggested you
decrease intensity by 1 from your optimal value, and decrease GPU threads to 1
with -g 1. It is also recommended to use --failover-only since the work is
effectively like a different block chain. If mining with a minirig, it is worth
adding the --bfl-range option.

Q: Are kernels from other mining software useable in nxminer?  
A: No, the APIs are slightly different between the different software and they
will not work.

Q: I run PHP on windows to access the API with the example miner.php. Why does
it fail when php is installed properly but I only get errors about Sockets not
working in the logs?  
A: http://us.php.net/manual/en/sockets.installation.php

Q: How do I get my BFL/Icarus/Lancelot/Cairnsmore device to auto-recognise?  
A: On linux, if the /dev/ttyUSB* devices don't automatically appear, the only
thing that needs to be done is to load the driver for them:
BFL: sudo modprobe ftdi_sio vendor=0x0403 product=0x6014
Icarus: sudo modprobe pl2303 vendor=0x067b product=0x230
Lancelot: sudo modprobe ftdi_sio vendor=0x0403 product=0x6001
Cairnsmore: sudo modprobe ftdi_sio product=0x8350 vendor=0x0403
On windows you must install the pl2303 or ftdi driver required for the device
pl2303: http://prolificusa.com/pl-2303hx-drivers/
ftdi: http://www.ftdichip.com/Drivers/VCP.htm

Q: On linux I can see the /dev/ttyUSB* devices for my Icarus FPGAs, but
nxminer can't mine on them  
A: Make sure you have the required priviledges to access the /dev/ttyUSB* devices:
 sudo ls -las /dev/ttyUSB*
will give output like:
 0 crw-rw---- 1 root dialout 188, 0 2012-09-11 13:49 /dev/ttyUSB0
This means your account must have the group 'dialout' or root priviledges
To permanently give your account the 'dialout' group:
 sudo usermod -G dialout -a \`whoami\`
Then logout and back in again

Q: What is stratum and how do I use it?  
A: Stratum is a protocol designed for pooled mining in such a way as to
minimise the amount of network communications, yet scale to hardware of any
speed. With versions of nxminer 2.8.0+, if a pool has stratum support, nxminer
will automatically detect it and switch to the support as advertised if it can.
Stratum uses direct TCP connections to the pool and thus it will NOT currently
work through a http proxy but will work via a socks proxy if you need to use
one. If you input the stratum port directly into your configuration, or use the
special prefix "stratum+tcp://" instead of "http://", nxminer will ONLY try to
use stratum protocol mining. The advantages of stratum to the miner are no
delays in getting more work for the miner, less rejects across block changes,
and far less network communications for the same amount of mining hashrate. If
you do NOT wish nxminer to automatically switch to stratum protocol even if it
is detected, add the --fix-protocol option.

Q: Why don't the statistics add up: Accepted, Rejected, Stale, Hardware Errors,
Diff1 Work, etc. when mining greater than 1 difficulty shares?  
A: As an example, if you look at 'Difficulty Accepted' in the RPC API, the number
of difficulty shares accepted does not usually exactly equal the amount of work
done to find them. If you are mining at 8 difficulty, then you would expect on
average to find one 8 difficulty share, per 8 single difficulty shares found.
However, the number is actually random and converges over time, it is an average,
not an exact value, thus you may find more or less than the expected average.
