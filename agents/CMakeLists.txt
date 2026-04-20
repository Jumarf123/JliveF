cmake_minimum_required(VERSION 3.20)
project(JVMTI_Agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_SHARED_LIBRARY_PREFIX "")

set(AGENT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/agent.cpp)
set(AGENT_INC ${CMAKE_CURRENT_SOURCE_DIR}/include)

function(resolve_jdk_include_dirs version out_var)
  set(candidates)

  foreach(env_name IN ITEMS JAVA${version}_HOME JDK${version}_HOME JAVA_HOME JDK_HOME)
    if(DEFINED ENV{${env_name}} AND NOT "$ENV{${env_name}}" STREQUAL "")
      list(APPEND candidates "$ENV{${env_name}}")
    endif()
  endforeach()

  file(GLOB versioned_candidates
    "C:/Program Files/Eclipse Adoptium/jdk-${version}*"
    "C:/Program Files/Java/jdk-${version}*")
  list(APPEND candidates ${versioned_candidates})

  if(version GREATER 8)
    file(GLOB modern_candidates
      "C:/Program Files/Eclipse Adoptium/jdk-2*"
      "C:/Program Files/Java/jdk-2*"
      "C:/Program Files/Eclipse Adoptium/jdk-1[7-9]*"
      "C:/Program Files/Java/jdk-1[7-9]*")
    list(APPEND candidates ${modern_candidates})
  endif()

  file(GLOB fallback_candidates
    "C:/Program Files/Eclipse Adoptium/jdk-*"
    "C:/Program Files/Java/jdk-*")
  list(APPEND candidates ${fallback_candidates})
  list(REMOVE_DUPLICATES candidates)

  foreach(candidate IN LISTS candidates)
    if(EXISTS "${candidate}/include/jni.h" AND EXISTS "${candidate}/include/win32/jni_md.h")
      set(${out_var}
        "${candidate}/include"
        "${candidate}/include/win32"
        PARENT_SCOPE)
      message(STATUS "Using JDK headers for Java ${version}: ${candidate}")
      return()
    endif()
  endforeach()

  message(FATAL_ERROR "Could not locate JDK headers for Java ${version}. Set JAVA${version}_HOME or JAVA_HOME.")
endfunction()

function(make_agent version)
  resolve_jdk_include_dirs(${version} JDK_INCLUDE_DIRS)
  add_library(JVMTI_Agent_${version} SHARED ${AGENT_SRC})
  target_include_directories(JVMTI_Agent_${version} PRIVATE ${AGENT_INC} ${JDK_INCLUDE_DIRS})
  target_compile_definitions(JVMTI_Agent_${version} PRIVATE TARGET_JAVA_VERSION=${version})
  target_link_libraries(JVMTI_Agent_${version} PRIVATE Rpcrt4)
  if(MSVC)
    set_property(TARGET JVMTI_Agent_${version} PROPERTY
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  else()
    # Statically link libstdc++/libgcc to avoid runtime DLL dependencies inside the target JVM.
    target_link_options(JVMTI_Agent_${version} PRIVATE -static -static-libstdc++ -static-libgcc)
  endif()
  set_target_properties(JVMTI_Agent_${version} PROPERTIES OUTPUT_NAME "JVMTI_Agent")

  if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(out_dir ${CMAKE_CURRENT_SOURCE_DIR}/x86/java${version})
  else()
    set(out_dir ${CMAKE_CURRENT_SOURCE_DIR}/java${version})
  endif()
  file(MAKE_DIRECTORY ${out_dir})
  set_target_properties(JVMTI_Agent_${version} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${out_dir}
    ARCHIVE_OUTPUT_DIRECTORY ${out_dir}
    LIBRARY_OUTPUT_DIRECTORY ${out_dir})

  foreach(cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    string(TOUPPER ${cfg} cfg_upper)
    set_target_properties(JVMTI_Agent_${version} PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY_${cfg_upper} ${out_dir}
      ARCHIVE_OUTPUT_DIRECTORY_${cfg_upper} ${out_dir}
      LIBRARY_OUTPUT_DIRECTORY_${cfg_upper} ${out_dir})
  endforeach()
endfunction()

make_agent(8)
make_agent(17)
make_agent(21)
