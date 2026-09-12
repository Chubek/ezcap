# ---------------------------------------------------------------------------
# Browser extension build (Chromium + Firefox).
#
# All extension build logic lives here; the root CMakeLists only includes
# this subdirectory. The TypeScript sources are compiled and assembled by
# the extension's own Node build script (package.json -> build.mjs) so that
# manual builds and CMake builds produce identical dist/ trees.
#
#   cmake --build ...             -> builds dist/chromium and dist/firefox
#   -DCMAKE_BUILD_EXT_ARCHIVE=ON  -> additionally packages loadable archives
#
# The build degrades honestly: when node/npm (or a TypeScript compiler) is
# unavailable the extension target is skipped and the rest of ezcap still
# builds.
# ---------------------------------------------------------------------------

option(CMAKE_BUILD_EXT_ARCHIVE
  "Package browser-loadable extension archives (Chromium .zip, Firefox .xpi)"
  OFF)

set(EZCAP_EXTENSION_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(EZCAP_EXTENSION_DIST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dist")

find_program(EZCAP_NPM_EXECUTABLE NAMES npm)
find_program(EZCAP_NODE_EXECUTABLE NAMES node)

# `npm run build` resolves a locally installed tsc first (the package.json
# devDependency) and falls back to one on PATH.
set(_ezcap_local_tsc "${EZCAP_EXTENSION_SOURCE_DIR}/node_modules/.bin/tsc")
find_program(EZCAP_TSC_EXECUTABLE NAMES tsc)

if(NOT EZCAP_NPM_EXECUTABLE OR NOT EZCAP_NODE_EXECUTABLE)
  message(STATUS "ezcap: node/npm not found; browser extension build disabled")
  return()
endif()
if(NOT EXISTS "${_ezcap_local_tsc}" AND NOT EZCAP_TSC_EXECUTABLE)
  message(STATUS "ezcap: TypeScript compiler not found; browser extension build "
                 "disabled (run: npm --prefix extension install)")
  return()
endif()

# Rebuild when any TypeScript source, manifest, shared asset, or build
# script changes.
file(GLOB_RECURSE _ezcap_extension_sources CONFIGURE_DEPENDS
  "${EZCAP_EXTENSION_SOURCE_DIR}/shared/src/*.ts"
  "${EZCAP_EXTENSION_SOURCE_DIR}/shared/styles/*"
  "${EZCAP_EXTENSION_SOURCE_DIR}/shared/icons/*"
  "${EZCAP_EXTENSION_SOURCE_DIR}/chromium/src/*.ts"
  "${EZCAP_EXTENSION_SOURCE_DIR}/chromium/manifest.json"
  "${EZCAP_EXTENSION_SOURCE_DIR}/firefox/src/*.ts"
  "${EZCAP_EXTENSION_SOURCE_DIR}/firefox/manifest.json")

set(EZCAP_EXTENSION_STAMP "${CMAKE_CURRENT_BINARY_DIR}/ezcap_extension.stamp")

add_custom_command(
  OUTPUT "${EZCAP_EXTENSION_STAMP}"
  COMMAND "${EZCAP_NPM_EXECUTABLE}" run build
  COMMAND "${CMAKE_COMMAND}" -E touch "${EZCAP_EXTENSION_STAMP}"
  WORKING_DIRECTORY "${EZCAP_EXTENSION_SOURCE_DIR}"
  DEPENDS
    ${_ezcap_extension_sources}
    "${EZCAP_EXTENSION_SOURCE_DIR}/package.json"
    "${EZCAP_EXTENSION_SOURCE_DIR}/tsconfig.json"
    "${EZCAP_EXTENSION_SOURCE_DIR}/build.mjs"
  COMMENT "Building ezcap browser extension (chromium + firefox)"
  VERBATIM)

add_custom_target(ezcap_extension ALL DEPENDS "${EZCAP_EXTENSION_STAMP}")

if(CMAKE_BUILD_EXT_ARCHIVE)
  set(_ezcap_chromium_archive
    "${CMAKE_CURRENT_BINARY_DIR}/ezcap-chromium-${PROJECT_VERSION}.zip")
  set(_ezcap_firefox_archive
    "${CMAKE_CURRENT_BINARY_DIR}/ezcap-firefox-${PROJECT_VERSION}.xpi")

  # An XPI is a plain ZIP, and both browsers expect the extension's files
  # at the archive root (manifest.json included), not nested in a directory.
  add_custom_command(
    OUTPUT "${_ezcap_chromium_archive}"
    COMMAND "${CMAKE_COMMAND}" -E tar cf "${_ezcap_chromium_archive}"
            --format=zip -- .
    WORKING_DIRECTORY "${EZCAP_EXTENSION_DIST_DIR}/chromium"
    DEPENDS "${EZCAP_EXTENSION_STAMP}"
    COMMENT "Packaging Chromium extension archive"
    VERBATIM)
  add_custom_command(
    OUTPUT "${_ezcap_firefox_archive}"
    COMMAND "${CMAKE_COMMAND}" -E tar cf "${_ezcap_firefox_archive}"
            --format=zip -- .
    WORKING_DIRECTORY "${EZCAP_EXTENSION_DIST_DIR}/firefox"
    DEPENDS "${EZCAP_EXTENSION_STAMP}"
    COMMENT "Packaging Firefox extension archive"
    VERBATIM)

  add_custom_target(ezcap_extension_archive ALL
    DEPENDS "${_ezcap_chromium_archive}" "${_ezcap_firefox_archive}")
  add_dependencies(ezcap_extension_archive ezcap_extension)
endif()
