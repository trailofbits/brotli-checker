cmake_minimum_required(VERSION 3.24)
project(brotli_known_answers NONE)
include(FetchContent)
# Download and unpack pinned dependencies only; do not configure or execute them.
file(READ "${CMAKE_CURRENT_LIST_DIR}/answers.json" answers)
string(JSON count LENGTH "${answers}")
math(EXPR last "${count} - 1")
foreach(i RANGE ${last})
  string(JSON version GET "${answers}" ${i} version)
  string(JSON sha256 GET "${answers}" ${i} archive_sha256)
  FetchContent_Populate(brotli_${i}
    URL "https://codeload.github.com/google/brotli/tar.gz/refs/tags/v${version}"
    URL_HASH "SHA256=${sha256}"
    SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/.deps/brotli-${version}")
endforeach()
