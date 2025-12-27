cmake_minimum_required(VERSION 3.14)
project(mxui_client LANGUAGES CXX)

set(BINARY_NAME "mxui_client")
set(APPLICATION_ID "com.mxui.client")

cmake_policy(SET CMP0063 NEW)

set(CMAKE_INSTALL_RPATH "@executable_path/Frameworks")

# Configure build options.
get_property(IS_MULTICONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(IS_MULTICONFIG)
  set(CMAKE_CONFIGURATION_TYPES "Debug;Profile;Release"
    CACHE STRING "" FORCE)
else()
  if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE
      STRING "Flutter build mode" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
      "Debug" "Profile" "Release")
  endif()
endif()

set(CMAKE_EXE_LINKER_FLAGS_PROFILE "${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
set(CMAKE_SHARED_LINKER_FLAGS_PROFILE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE}")
set(CMAKE_C_FLAGS_PROFILE "${CMAKE_C_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_PROFILE "${CMAKE_CXX_FLAGS_RELEASE}")

# Compilation settings that should be applied to most targets.
function(APPLY_STANDARD_SETTINGS TARGET)
  target_compile_features(${TARGET} PUBLIC cxx_std_14)
  target_compile_options(${TARGET} PRIVATE -Wall -Werror)
  target_compile_options(${TARGET} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:-O3>")
  target_compile_definitions(${TARGET} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")
endfunction()

set(FLUTTER_MANAGED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/flutter")

# Flutter library and tool build rules.
add_subdirectory(${FLUTTER_MANAGED_DIR})

# Application build
add_executable(${BINARY_NAME} MACOSX_BUNDLE
  "MainFlutterWindow.swift"
  "AppDelegate.swift"
)

set_target_properties(${BINARY_NAME} PROPERTIES
  BUNDLE True
  MACOSX_BUNDLE_GUI_IDENTIFIER ${APPLICATION_ID}
  MACOSX_BUNDLE_BUNDLE_NAME ${BINARY_NAME}
  MACOSX_BUNDLE_BUNDLE_VERSION "1.0.0"
  MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0.0"
)

apply_standard_settings(${BINARY_NAME})
target_link_libraries(${BINARY_NAME} PRIVATE "-framework Cocoa")
target_link_libraries(${BINARY_NAME} PRIVATE "-framework FlutterMacOS")
target_link_libraries(${BINARY_NAME} PRIVATE flutter_assemble)

add_dependencies(${BINARY_NAME} flutter_assemble)

# Generated plugin build rules
include(flutter/generated_plugins.cmake)

# === Installation ===
include(BundleUtilities)

install(TARGETS ${BINARY_NAME}
  BUNDLE DESTINATION .
  COMPONENT Runtime)
