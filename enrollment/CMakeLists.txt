add_executable(nirantara-enrollment
    src/main.c
    src/config.c
    src/kms.c
    src/enrollment.c
    src/http.c
)

target_include_directories(nirantara-enrollment
    PRIVATE
        include
)

target_link_libraries(nirantara-enrollment
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        CURL::libcurl
)
