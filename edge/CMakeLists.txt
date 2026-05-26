add_executable(nirantara-edge
    src/main.c
    src/buffer.c
    src/sync.c
)

target_include_directories(nirantara-edge
    PRIVATE
        include
        ${SQLITE3_INCLUDE_DIRS}
        ${LIBPQ_INCLUDE_DIRS}
        ${MOSQUITTO_INCLUDE_DIRS}
)

target_link_libraries(nirantara-edge
    PRIVATE
        ${SQLITE3_LIBRARIES}
        ${LIBPQ_LIBRARIES}
        ${MOSQUITTO_LIBRARIES}
        Threads::Threads
)

target_compile_options(nirantara-edge PRIVATE
    ${SQLITE3_CFLAGS_OTHER}
    ${LIBPQ_CFLAGS_OTHER}
    ${MOSQUITTO_CFLAGS_OTHER}
)
