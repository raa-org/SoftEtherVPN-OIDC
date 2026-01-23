file(GLOB SOURCES_CEDAR "*.c")
file(GLOB HEADERS_CEDAR "*.h")

if(WIN32)
  enable_language(CXX)
  file(GLOB SOURCES_CEDAR_CPP "*.cpp")
endif()

if(WIN32)
  add_library(cedar STATIC ${SOURCES_CEDAR} ${SOURCES_CEDAR_CPP} ${HEADERS_CEDAR})
else()
  add_library(cedar SHARED ${SOURCES_CEDAR} ${SOURCES_CEDAR_CPP} ${HEADERS_CEDAR})
endif()

set_target_properties(cedar
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(cedar PUBLIC mayaqua)

if(SKIP_CPU_FEATURES)
  set(BLAKE2_SRC_PATH ${TOP_DIRECTORY}/3rdparty/BLAKE2/ref)
  set(BLAKE2_SRC      ${BLAKE2_SRC_PATH}/blake2s-ref.c)
else()
  cmake_host_system_information(RESULT HAS_SSE2 QUERY HAS_SSE2)
  if(HAS_SSE2)
    set(BLAKE2_SRC_PATH ${TOP_DIRECTORY}/3rdparty/BLAKE2/sse)
    set(BLAKE2_SRC      ${BLAKE2_SRC_PATH}/blake2s.c)
  else()
    set(BLAKE2_SRC_PATH ${TOP_DIRECTORY}/3rdparty/BLAKE2/ref)
    set(BLAKE2_SRC      ${BLAKE2_SRC_PATH}/blake2s-ref.c)
  endif()
endif()

target_include_directories(cedar PUBLIC ${BLAKE2_SRC_PATH})
target_sources(cedar PRIVATE ${BLAKE2_SRC})

if(HAS_SSE2)
  # If SSE2 is enabled, a build failure occurs with MSVC because it doesn't define "__SSE2__".
  # The fix consists in defining "HAVE_SSE2" manually, effectively overriding the check.
  set_property(SOURCE ${BLAKE2_SRC} PROPERTY COMPILE_DEFINITIONS "HAVE_SSE2")
endif()

if(VCPKG_TARGET_TRIPLET)
  find_package(unofficial-sodium CONFIG REQUIRED)
  target_link_libraries(cedar PUBLIC unofficial-sodium::sodium)

  # --- LibJWT via FetchContent, wired to vcpkg deps ---
  include(FetchContent)
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

  # Use vcpkg's OpenSSL + Jansson
  find_package(OpenSSL REQUIRED)
  find_package(jansson CONFIG REQUIRED)

  # libjwt links to a target/library named "jansson".
  # Create an alias so that "jansson" resolves to vcpkg's jansson::jansson
  if (TARGET jansson::jansson AND NOT TARGET jansson)
    add_library(jansson ALIAS jansson::jansson)
  endif()

  # Force OpenSSL backend in libjwt, disable others
  set(WITH_OPENSSL ON  CACHE BOOL "" FORCE)
  set(WITH_GNUTLS  OFF CACHE BOOL "" FORCE)
  set(WITH_MBEDTLS OFF CACHE BOOL "" FORCE)
  set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(BUILD_TESTING  OFF CACHE BOOL "" FORCE)

  FetchContent_Declare(
    libjwt
    GIT_REPOSITORY https://github.com/benmcollins/libjwt.git
    GIT_TAG v1.17.2
  )
  FetchContent_GetProperties(libjwt)
  if(NOT libjwt_POPULATED)
    FetchContent_Populate(libjwt)
    add_subdirectory(${libjwt_SOURCE_DIR} ${libjwt_BINARY_DIR} EXCLUDE_FROM_ALL)
  endif()

  # Link cedar to libjwt; PUBLIC so final exe gets it automatically
  if (TARGET LibJWT::jwt)
    target_link_libraries(cedar PUBLIC LibJWT::jwt)
  elseif (TARGET jwt)
    target_link_libraries(cedar PUBLIC jwt)
  else()
    message(FATAL_ERROR "libjwt fetched but CMake target not found (expected LibJWT::jwt or jwt).")
  endif()
else()
  find_package(PkgConfig REQUIRED)
  pkg_search_module(SODIUM libsodium REQUIRED)
  target_include_directories(cedar PUBLIC ${SODIUM_INCLUDE_DIRS})
  if(NOT ("$ENV{TRAVIS_CPU_ARCH}" STREQUAL ppc64le))
    target_link_libraries(cedar PUBLIC $<IF:$<BOOL:SODIUM_LINK_LIBRARIES>,${SODIUM_LINK_LIBRARIES},${SODIUM_LIBRARIES}>)
  else()
    # TODO: investigate why on ppc64le the use of SODIUM_LINK_LIBRARIES causes undefined references to libsodium functions.
    target_link_libraries(cedar PUBLIC ${SODIUM_LIBRARIES})
  endif()

  # libjwt - brings jansson & openssl transitively via pkg-config
  pkg_check_modules(LIBJWT REQUIRED libjwt)
  target_include_directories(cedar PRIVATE ${LIBJWT_INCLUDE_DIRS})
  target_link_libraries(cedar PRIVATE ${LIBJWT_LIBRARIES})
endif()

set(OIDC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/Oidc")

target_sources(cedar PRIVATE
    ${OIDC_DIR}/OidcDefs.h
    ${OIDC_DIR}/OidcLog.h
    ${OIDC_DIR}/OidcClient.h
    ${OIDC_DIR}/OidcClient.c
    ${OIDC_DIR}/OidcServer.h
    ${OIDC_DIR}/OidcServer.c
    ${OIDC_DIR}/OidcClientCore.h
    ${OIDC_DIR}/OidcClientCore.c
    ${OIDC_DIR}/OidcHttp.h
    ${OIDC_DIR}/OidcHttp.c
    ${OIDC_DIR}/OidcLoopback.h
    ${OIDC_DIR}/OidcLoopback.c
    ${OIDC_DIR}/OidcUrlEncoding.h
    ${OIDC_DIR}/OidcUrlEncoding.c
    ${OIDC_DIR}/OidcSecureStore.h
    ${OIDC_DIR}/OidcPkce.h
    ${OIDC_DIR}/OidcPkce.c
    ${OIDC_DIR}/OidcInteractiveUI.h
    ${OIDC_DIR}/OidcJwt.h
    ${OIDC_DIR}/OidcJwt.c
)

if (WIN32)
    target_sources(cedar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Oidc/OidcSecureStoreWin32.c)

    target_sources(cedar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Oidc/OidcInteractiveUIWin32.c)
    target_sources(cedar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Oidc/OidcEmbededViewWin32.h)
    target_sources(cedar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Oidc/OidcEmbededViewWin32.cpp)
else()
    target_sources(cedar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Oidc/OidcSecureStoreStub.c)

    target_sources(cedar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Oidc/OidcInteractiveUIStub.c)
endif()


target_include_directories(cedar PRIVATE ${OIDC_DIR})

if(WIN32)
  set_target_properties(cedar
    PROPERTIES
    COMPILE_PDB_NAME "cedar"
    COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  target_include_directories(cedar PRIVATE winpcap)
  target_link_libraries(cedar PRIVATE comctl32.lib urlmon.lib shell32.lib ole32.lib crypt32.lib)

  # Prefer vcpkg's imported target if available
  find_package(Microsoft.Web.WebView2 CONFIG QUIET)
  if (TARGET Microsoft.Web.WebView2::WebView2Loader OR TARGET Microsoft.Web.WebView2::WebView2)
    # Link against the vcpkg-provided target
    if (TARGET Microsoft.Web.WebView2::WebView2Loader)
      target_link_libraries(cedar PRIVATE Microsoft.Web.WebView2::WebView2Loader ole32)
    else()
      target_link_libraries(cedar PRIVATE Microsoft.Web.WebView2::WebView2 ole32)
    endif()

  else()
    # Fallback
    set(WEBVIEW2_SDK_ROOT "" CACHE PATH "Path to Microsoft.Web.WebView2 build/native directory")

    set(_WV2_CANDIDATE_DIRS
            "${WEBVIEW2_SDK_ROOT}"
            "$ENV{USERPROFILE}/.nuget/packages/microsoft.web.webview2/*/build/native"
            "${CMAKE_SOURCE_DIR}/3rdparty/Microsoft.Web.WebView2/build/native"
    )

    set(_WV2_SEARCH_DIRS "")
    foreach(dir IN LISTS _WV2_CANDIDATE_DIRS)
      file(GLOB _m "${dir}")
      list(APPEND _WV2_SEARCH_DIRS ${_m})
    endforeach()

    find_path(WEBVIEW2_INCLUDE_DIR
            WebView2.h
            PATH_SUFFIXES include
            PATHS ${_WV2_SEARCH_DIRS}
            REQUIRED
    )

    # Accept both static and DLL import lib names
    find_library(WEBVIEW2_LOADER_LIB
            NAMES WebView2LoaderStatic WebView2Loader WebView2Loader.dll.lib
            PATH_SUFFIXES x64 X64 lib
            PATHS ${_WV2_SEARCH_DIRS}
            REQUIRED
    )

    target_include_directories(cedar PRIVATE ${WEBVIEW2_INCLUDE_DIR})
    target_link_libraries(cedar PRIVATE ${WEBVIEW2_LOADER_LIB} ole32)
  endif()
endif()

if(UNIX)
  find_package(Curses REQUIRED)
  find_library(LIB_READLINE readline)

  target_link_libraries(cedar PRIVATE ${CURSES_LIBRARIES} ${LIB_READLINE})

  if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    target_link_libraries(cedar PRIVATE mayaqua pcap)
  endif()
endif()

# Version
add_definitions(-DCEDAR_VERSION_MAJOR=${PROJECT_VERSION_MAJOR} -DCEDAR_VERSION_MINOR=${PROJECT_VERSION_MINOR} -DCEDAR_VERSION_BUILD=${PROJECT_VERSION_PATCH})

# Builder
if(UNIX)
  add_definitions(-DBUILDER_NAME="$ENV{USER}")
elseif(WIN32)
  add_definitions(-DBUILDER_NAME="$ENV{USERNAME}")
endif()

cmake_host_system_information(RESULT BUILDER_HOSTNAME QUERY HOSTNAME)

add_definitions(-DBUILD_PLACE="${BUILDER_HOSTNAME}")

# Remove leading 0 from date and time
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_DAY "${DATE_DAY}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_MONTH "${DATE_MONTH}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_YEAR "${DATE_YEAR}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_HOUR "${TIME_HOUR}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_MINUTE "${TIME_MINUTE}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_SECOND "${TIME_SECOND}")

add_definitions(-DBUILD_DATE_D=${BUILD_DAY} -DBUILD_DATE_M=${BUILD_MONTH} -DBUILD_DATE_Y=${BUILD_YEAR})
add_definitions(-DBUILD_DATE_HO=${BUILD_HOUR} -DBUILD_DATE_MI=${BUILD_MINUTE} -DBUILD_DATE_SE=${BUILD_SECOND})

if(UNIX)
  install(TARGETS cedar
    COMPONENT "common"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  )
endif()
