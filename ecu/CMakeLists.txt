# Core ECU logic as a library so both the target binary and the tests link it.
add_library(ecu_core STATIC
    src/isotp.c
    src/uds.c
)
target_include_directories(ecu_core PUBLIC include)

add_executable(ecu src/main.c)
target_link_libraries(ecu PRIVATE ecu_core)

if(BUILD_TESTING)
    foreach(t isotp uds security)
        add_executable(test_${t} tests/test_${t}.c)
        target_link_libraries(test_${t} PRIVATE ecu_core)
        add_test(NAME ${t} COMMAND test_${t})
    endforeach()
endif()
