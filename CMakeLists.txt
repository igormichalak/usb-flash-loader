cmake_minimum_required(VERSION 3.17)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(PICO_BOARD pico2)
set(PICO_PLATFORM rp2350-arm-s)
set(BOARD raspberry_pi_pico2)
set(PICO_TINYUSB_PATH ${CMAKE_CURRENT_LIST_DIR}/tinyusb)

include(pico_sdk_import.cmake)

project(firmware C CXX ASM)
add_executable(firmware)

pico_sdk_init()
pico_enable_stdio_usb(firmware 0)
pico_enable_stdio_uart(firmware 0)
pico_add_extra_outputs(firmware)

target_sources(firmware PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/firmware.c
    ${CMAKE_CURRENT_LIST_DIR}/usb_descriptors.c
)

target_include_directories(firmware PUBLIC ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(firmware PUBLIC 
    pico_stdlib pico_multicore pico_unique_id
    hardware_gpio hardware_spi
    tinyusb_device tinyusb_board
)
