# USB Flash Loader

Firmware for the RP2350 microcontroller that turns it into a USB device (with TinyUSB stack) supporting flashing SPI flash memories with files at user-specified offsets. And a convenient CLI application.

Tested with the Microchip SST25VF040B non-paged SPI flash memory.

## The firmware architecture

The RP2350 SRAM is separated into four 64 kB independent command & data buffers.  
The two RP2350 cores are used for different tasks, but they exchange data via these buffers.   
For synchronization, each buffer has an atomic lock, along with information about its fill size.  

The first core receives a stream of commands and data via USB and fills the unlocked buffers with them, then locking them.

The second cores takes the locked buffers and executes the commands it finds inside, including erase and flash commands. It does this by sending flash-specific commands over the SPI protocol in a continous mode (Auto Address Increment Programming, AAI for short).

## The CLI flashtool

For more information on how to use the CLI flashtool, use the program flag `-help`.
