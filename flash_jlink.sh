#!/bin/sh

rpi-openocd -f interface/jlink.cfg \
            -f target/rp2350.cfg \
            -c "adapter speed 4000" \
            -c "program build/firmware.elf verify reset exit"
