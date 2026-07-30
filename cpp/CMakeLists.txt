cmake_minimum_required(VERSION 3.15)
project(aegis_cpp)

# Standard C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Trouver Python
find_package(Python REQUIRED COMPONENTS Interpreter Development)

# Trouver pybind11 via pip
#execute_process(
#    COMMAND "${Python_EXECUTE}" -c
#        "import pybind11; print(pybind11.get_cmake_dir())"
#    OUTPUT_VARIABLE PYBIND11_CMAKE_DIR
#    OUTPUT_STRIP_TRAILING_WHITESPACE
#)
#list(APPEND CMAKE_PREFIX_PATH "$PYBIND11_CMAKE_DIR")


# pybind11 - chemin explicite pour éviter les problèmes d'espaces
set(pybind11_DIR
    "C:/Users/DELL LATITUDE 5420/AppData/Roaming/Python/Python314/site-packages/pybind11/share/cmake/pybind11"
)

find_package(pybind11 REQUIRED CONFIG)



# OpenSSL
set(OPENSSL_ROOT_DIR "C:/Program Files/mingw64")
set(OPENSSL_INCLUDE_DIR "C:/Program Files/mingw64/include")
set(OPENSSL_LIBRARIES
    "C:/Program Files/mingw64/lib/VC/x64/MD/libssl.lib"
    "C:/Program Files/mingw64/lib/VC/x64/MD/libcrypto.lib"
)

#Module Python
pybind11_add_module(aegis_cpp src/aegis_module.cpp)

target_include_directories(aegis_cpp PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(aegis_cpp PRIVATE
    ${OPENSSL_LIBRARIES}
)

# Copie le .pyd dans cpp/bin/ après compilation
add_custom_command(TARGET aegis_cpp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:aegis_cpp>
        "${CMAKE_SOURCE_DIR}/bin/$<TARGET_FILE_NAME:aegis_cpp>"
)



