add_library(nirantara-net SHARED
    src/net.c
    src/tls.c
    src/keystore.c
    src/enroll.c
    src/mqtt.c
)

target_include_directories(nirantara-net
    PUBLIC  include
    PRIVATE include/nirantara
)

target_link_libraries(nirantara-net
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
        ${MOSQUITTO_LIBRARIES}
)

target_include_directories(nirantara-net PRIVATE ${MOSQUITTO_INCLUDE_DIRS})
target_compile_options(nirantara-net PRIVATE ${MOSQUITTO_CFLAGS_OTHER})

set_target_properties(nirantara-net PROPERTIES
    VERSION   0.1.0
    SOVERSION 0
    PUBLIC_HEADER include/nirantara/net.h
)
