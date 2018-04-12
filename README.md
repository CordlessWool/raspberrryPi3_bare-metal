# Ethernet Raspberry Pi 3 bare metal project

>This is an small Raspberry Pi Project, based on [USPI](https://github.com/rsta2/uspi).

Main function is to receive and replay arp packages, to get the Pi recognized by router and others in the network. Also UDP with Checksum is implemented to easy send UDP-Frames over Ethernet. To send something call `send_udp_to(u8 ip[4], char * message, int port)`. 

Based on UDP there is a function to send NTP requests to an SNTP `void send_SNTP(u8 ip[4])`

Build Samples
-------

The sample programs in the *sample/* subdirectory and all required libraries can be build from USPi root by:

`./makeall clean`  
`./makeall`

The ready build *kernel.img* image file is in the same directory where its source code is. Copy it on a SD(HC) card along with the firmware files *bootcode.bin*, *fixup.dat* and *start.elf* which can be get [here](https://github.com/raspberrypi/firmware/tree/master/boot). Put the SD(HC) card into your Raspberry Pi and start it.


