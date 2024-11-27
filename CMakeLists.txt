cmake_minimum_required(VERSION 3.17)

set(PICO_BOARD pico2)
set(PICO_PLATFORM rp2350-arm-s)

include(pico_sdk_import.cmake)

project(firmware C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()

add_executable(firmware firmware.c)

pico_enable_stdio_usb(firmware 1)
pico_enable_stdio_uart(firmware 0)

pico_add_extra_outputs(firmware)

target_link_libraries(firmware pico_stdlib pico_multicore hardware_gpio hardware_spi)
