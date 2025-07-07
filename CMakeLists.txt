cmake_minimum_required(VERSION 3.10)
project(TableTopVault)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find system packages
find_package(Boost 1.74 REQUIRED COMPONENTS system)
include_directories(${Boost_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

include(FetchContent)

FetchContent_Declare(
  yaml_cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG master
)
FetchContent_MakeAvailable(yaml_cpp)


find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP true
  )
  FetchContent_MakeAvailable(json)
endif()


include(FetchContent)

FetchContent_Declare(
  json_validator
  GIT_REPOSITORY https://github.com/pboettch/json-schema-validator.git
  GIT_TAG main
)
FetchContent_MakeAvailable(json_validator)

pkg_check_modules(SODIUM REQUIRED libsodium)

# Daemon executable
add_executable(vault_daemon vault_daemon.cpp)
target_link_libraries(vault_daemon
    PRIVATE
      ${Boost_LIBRARIES}
      OpenSSL::SSL OpenSSL::Crypto
      CURL::libcurl
      ${SODIUM_LIBRARIES}
      nlohmann_json::nlohmann_json
      nlohmann_json_schema_validator
      yaml-cpp
)
target_include_directories(vault_daemon
    PRIVATE
      ${SODIUM_INCLUDE_DIRS}
)

# GUI executable
find_package(Qt5 REQUIRED COMPONENTS Widgets Core Network)
add_executable(vault_gui vault_gui.cpp)
target_link_libraries(vault_gui
    PRIVATE
      Qt5::Widgets Qt5::Core Qt5::Network
      ${SODIUM_LIBRARIES}
      nlohmann_json::nlohmann_json 
      yaml-cpp
)
target_include_directories(vault_gui
    PRIVATE ${SODIUM_INCLUDE_DIRS}
)
set_target_properties(vault_gui PROPERTIES AUTOMOC ON)

# CLI helper to request a token from the vault daemon
add_executable(vault_requests vault_requests.cpp)
target_link_libraries(vault_requests
    PRIVATE
      ${Boost_LIBRARIES}
      ${SODIUM_LIBRARIES}
      nlohmann_json::nlohmann_json
      OpenSSL::SSL
      OpenSSL::Crypto
      yaml-cpp
)
target_include_directories(vault_requests
    PRIVATE
      ${SODIUM_INCLUDE_DIRS}
)

# Install
install(TARGETS vault_daemon RUNTIME DESTINATION bin)
install(TARGETS vault_gui RUNTIME DESTINATION bin)
install(TARGETS vault_requests RUNTIME DESTINATION bin)
