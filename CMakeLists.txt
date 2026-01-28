cmake_minimum_required(VERSION 3.16)
project(sharkai C CXX)

find_package(PkgConfig REQUIRED)

# Dependencies
pkg_check_modules(JSONC REQUIRED json-c)
pkg_check_modules(GLIB REQUIRED glib-2.0 gobject-2.0)
pkg_check_modules(WIRESHARK REQUIRED wireshark)

# ---- Qt detection (prefer Qt6, fallback to Qt5) ----
find_package(Qt6 COMPONENTS Widgets Core Network QUIET)

if (Qt6_FOUND)
    message(STATUS "Using Qt6")
    set(QT_PACKAGE Qt6)
    set(QT_WIDGETS_TARGET Qt6::Widgets)
    set(QT_CORE_TARGET Qt6::Core)
    set(QT_NETWORK_TARGET Qt6::Network)

else()
    find_package(Qt5 COMPONENTS Widgets Core Network QUIET)

    if (Qt5_FOUND)
        message(STATUS "Using Qt5")
        set(QT_PACKAGE Qt5)
        set(QT_WIDGETS_TARGET Qt5::Widgets)
        set(QT_CORE_TARGET Qt5::Core)
        set(QT_NETWORK_TARGET Qt5::Network)
    else()
        message(FATAL_ERROR
            "Neither Qt6 nor Qt5 was found.\n"
            "Please install Qt development packages:\n"
            "  - Qt6: qt6-base-dev (Debian/Ubuntu), qt6-qtbase-devel (Fedora)\n"
            "  - Qt5: qtbase5-dev (Debian/Ubuntu), qt5-qtbase-devel (Fedora)"
        )
    endif()
endif()

# Debug / extract Qt include paths explicitly
get_target_property(QT_WIDGETS_INCLUDES ${QT_WIDGETS_TARGET} INTERFACE_INCLUDE_DIRECTORIES)
get_target_property(QT_CORE_INCLUDES ${QT_CORE_TARGET} INTERFACE_INCLUDE_DIRECTORIES)
get_target_property(QT_NETWORK_INCLUDES ${QT_NETWORK_TARGET} INTERFACE_INCLUDE_DIRECTORIES)

message(STATUS "Qt Widgets include dirs: ${QT_WIDGETS_INCLUDES}")
message(STATUS "Qt Core include dirs: ${QT_CORE_INCLUDES}")
message(STATUS "Qt Network include dirs: ${QT_NETWORK_INCLUDES}")

add_library(sharkai SHARED
    sharkai.c
    sharkai_dialog.cpp
    sharkai_config.c
    sharkai_qt_bridge.cpp
)

target_include_directories(sharkai PRIVATE
    ${QT_WIDGETS_INCLUDES}
    ${QT_CORE_INCLUDES}
    ${QT_NETWORK_INCLUDES}
    ${GLIB_INCLUDE_DIRS}
    ${JSONC_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    /usr/local/include/wireshark
)

# Library search path
target_link_directories(sharkai PRIVATE
    /usr/local/lib
)

# Link libraries
target_link_libraries(sharkai
    wireshark
    wsutil
    wiretap
    ${QT_WIDGETS_TARGET}
    ${QT_CORE_TARGET}
    ${QT_NETWORK_TARGET}
    ${GLIB_LIBRARIES}
    ${JSONC_LIBRARIES}
)

# Extra compiler flags from pkg-config (very important)
target_compile_options(sharkai PRIVATE
    ${WIRESHARK_CFLAGS_OTHER}
    ${GLIB_CFLAGS_OTHER}
)

set_target_properties(sharkai PROPERTIES
    PREFIX ""
)
