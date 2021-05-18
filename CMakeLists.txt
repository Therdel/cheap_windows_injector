cmake_minimum_required (VERSION 3.8)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    project("cliInjector")
    set(CMAKE_CXX_STANDARD 17)

    set(SOURCE_FILES
            src/main.cpp
            src/ProcMemAccess.cpp)

    add_executable(cliInjector ${SOURCE_FILES})

    target_include_directories(cliInjector
      PRIVATE ${cssHack_SOURCE_DIR}/src
      )

    # target_link_libraries(cliInjector stdc++fs)
    
    set_target_properties(cliInjector PROPERTIES
        # force 32bit compilation
        # source: https://stackoverflow.com/questions/5805874/the-proper-way-of-forcing-a-32-bit-compile-using-cmake
        COMPILE_OPTIONS "-m32"
        LINK_OPTIONS "-m32"

        # default to hidden symbols
        CXX_VISIBILITY_PRESET hidden
        )
endif()
