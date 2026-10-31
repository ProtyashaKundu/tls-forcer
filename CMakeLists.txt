cmake_minimum_required(VERSION 3.16)
project(tls_forcer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenSSL 3.0 REQUIRED)

add_library(tlsf STATIC src/tls_util.cpp src/client_core.cpp src/inspect.cpp)
target_include_directories(tlsf PUBLIC src)
target_link_libraries(tlsf PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(tlsf PUBLIC -Wall -Wextra)

foreach(tool tls_client tls_server tls_probe)
  add_executable(${tool} src/${tool}.cpp)
  target_link_libraries(${tool} PRIVATE tlsf)
endforeach()

# Dashboard: the HTML page is embedded into the binary at build time.
file(READ ${CMAKE_SOURCE_DIR}/web/dashboard.html DASHBOARD_HTML)
configure_file(src/dashboard_html.hpp.in ${CMAKE_BINARY_DIR}/generated/dashboard_html.hpp @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS web/dashboard.html)
add_executable(tls_dashboard src/tls_dashboard.cpp)
target_include_directories(tls_dashboard PRIVATE ${CMAKE_BINARY_DIR}/generated)
target_link_libraries(tls_dashboard PRIVATE tlsf)
