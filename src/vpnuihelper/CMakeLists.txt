if(NOT WIN32)
  message(FATAL_ERROR "VPN Client UI Helper is available only for Windows.")
endif()

#set(COMPONENT_NAME "VPN Client UI Helper")
#set(COMPONENT_INTERNAL_NAME "vpnuihelper")

add_executable(vpnuihelper WIN32
  "vpnuihelper.c"
  "vpnuihelper.rc"
  "vpnuihelper_version.h"
  "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
)

#get_filename_component(COMPONENT_FILE_NAME vpnuihelper NAME)
#set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

target_include_directories(vpnuihelper PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

set_target_properties(vpnuihelper
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpnuihelper cedar mayaqua)
