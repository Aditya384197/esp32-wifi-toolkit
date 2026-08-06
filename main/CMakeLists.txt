set(COMPONENT_SRCDIRS .)
set(COMPONENT_ADD_INCLUDEDIRS .)

idf_component_register(
    SRCS
        main.c
        utils.c
        scanner.c
        deauth.c
        beacon.c
        sniffer.c
        packet_analyzer.c
        handshake.c
        evil_twin.c
        pcapng.c
        storage.c
    INCLUDE_DIRS
        "."
    PRIV_REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        lwip
        esp_http_server
        mbedtls
        spiffs
        driver
        esp_timer
)

# 🔥 Size Optimization (App Size कम करने के लिए)
target_compile_options(${COMPONENT_LIB} PRIVATE 
    -Wno-format 
    -Wno-incompatible-pointer-types
    -Wno-error=int-conversion
    -Os                    # 🔥 Size Optimization (Speed की बजाय Size)
)

# 🔥 Partition Table का Path Set करें (नई partitions.csv के लिए)
set(IDF_PARTITION_TABLE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/partitions.csv)
