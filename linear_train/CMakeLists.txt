add_executable(lintrain)

target_sources(lintrain
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/linear_train.cpp
)

find_package(SEAL 3.5 REQUIRED)

target_link_libraries(lintrain PUBLIC SEAL::seal)

# IDEs should put the headers in a nice place
source_group(TREE "${PROJECT_SOURCE_DIR}" PREFIX "Common Files" FILES ${COMMON_FILES})

install(TARGETS lintrain
        CONFIGURATIONS Release
        RUNTIME DESTINATION ${PROJECT_SOURCE_DIR}/release)
