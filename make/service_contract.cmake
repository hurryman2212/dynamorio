# Fingerprint private protocols and matching launcher/runtime configuration.
# Receivers compare this before interpreting protocol-dependent record fields.
string(TOUPPER "${CMAKE_BUILD_TYPE}" DR_SERVICE_CONFIG)
file(SHA256 "${CMAKE_CURRENT_LIST_FILE}" DR_SERVICE_GENERATOR_DIGEST)
set(DR_SERVICE_CONTENT
    "${CMAKE_C_COMPILER_ID}:${CMAKE_C_COMPILER_VERSION}:${CMAKE_C_COMPILER_TARGET}:${CMAKE_SYSTEM_NAME}:${CMAKE_SYSTEM_PROCESSOR}:${CMAKE_SIZEOF_VOID_P}:${CMAKE_C_BYTE_ORDER}:${CMAKE_BUILD_TYPE}\n${CMAKE_C_FLAGS}\n${CMAKE_C_FLAGS_${DR_SERVICE_CONFIG}}\nmake/service_contract.cmake:${DR_SERVICE_GENERATOR_DIGEST}\n"
)
foreach(
  INPUT
  core/lib/dr_exec_resources.h
  core/lib/dr_thread_suspend.h
  core/lib/dr_events.h
  core/unix/exec_resources.c
  core/unix/thread_suspend.c
  core/unix/signal.c
  core/unix/os.c
  core/unix/os_private.h
  core/config.c
  libutil/dr_config.c)
  set(INPUT_PATH "${PROJECT_SOURCE_DIR}/${INPUT}")
  file(SHA256 "${INPUT_PATH}" DIGEST)
  string(APPEND DR_SERVICE_CONTENT "${INPUT}:${DIGEST}\n")
  set_property(
    DIRECTORY
    APPEND
    PROPERTY CMAKE_CONFIGURE_DEPENDS "${INPUT_PATH}")
endforeach()
string(SHA256 DR_SERVICE_CONTRACT_HASH "${DR_SERVICE_CONTENT}")
file(
  CONFIGURE
  OUTPUT
  "${BUILD_INCLUDE}/dr_service_contract.h"
  CONTENT
  "#ifndef DR_SERVICE_CONTRACT_H\n#define DR_SERVICE_CONTRACT_H\n#define DR_EXEC_RESOURCE_CONTRACT_HASH \"${DR_SERVICE_CONTRACT_HASH}\"\n#define DR_THREAD_SUSPEND_CONTRACT_HASH \"${DR_SERVICE_CONTRACT_HASH}\"\n#endif\n"
  @ONLY)

# Internal DR sources include the build root without exporting all API headers.
configure_file("${BUILD_INCLUDE}/dr_service_contract.h"
               "${PROJECT_BINARY_DIR}/dr_service_contract.h" COPYONLY)
