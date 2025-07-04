cmake_minimum_required(VERSION 3.10)
project(TableTopVault)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost 1.74 REQUIRED)
find_package(PkgConfig REQUIRED)

# fallback to FetchContent for nlohmann_json if not found
include(FetchContent)
FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP true
)
FetchContent_MakeAvailable(json)

pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(vault_daemon vault_daemon.cpp)
target_link_libraries(vault_daemon PRIVATE Boost::boost ${SODIUM_LIBRARIES} nlohmann_json::nlohmann_json)
target_include_directories(vault_daemon PRIVATE ${SODIUM_INCLUDE_DIRS})

if(BUILD_GUI)
    find_package(Qt5 REQUIRED COMPONENTS Widgets Core Network)
    add_executable(vault_gui vault_gui.cpp)
    target_link_libraries(vault_gui PRIVATE Qt5::Widgets Qt5::Core Qt5::Network ${SODIUM_LIBRARIES} nlohmann_json::nlohmann_json)
    target_include_directories(vault_gui PRIVATE ${SODIUM_INCLUDE_DIRS})
    set_target_properties(vault_gui PROPERTIES AUTOMOC ON)
endif()

install(TARGETS vault_daemon RUNTIME DESTINATION bin)
if(BUILD_GUI)
    install(TARGETS vault_gui RUNTIME DESTINATION bin)
endif()
