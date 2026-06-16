# Core ECU logic as a library so both the target binary and the tests link it.
add_library(ecu_core STATIC
    src/isotp.c
)
target_include_directories(ecu_core PUBLIC include)

add_executable(ecu src/main.c)
target_link_libraries(ecu PRIVATE ecu_core)

if(BUILD_TESTING)
    add_executable(test_isotp tests/test_isotp.c)
    target_link_libraries(test_isotp PRIVATE ecu_core)
    add_test(NAME isotp COMMAND test_isotp)
endif()
