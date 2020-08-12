cmake_minimum_required(VERSION 3.0)

project(MailMask C)

option(WITH_SYSTEMD "Install Systemd unit files" ON)
set(SYSTEMD_UNITDIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system" CACHE PATH "Systemd unit directory")
set(CONFIG_DIR "${CMAKE_INSTALL_PREFIX}/etc" CACHE PATH "Config directory")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
find_package(Milter REQUIRED)
find_package(MySQL REQUIRED)
find_package(LibConfig REQUIRED)

add_executable(mailmask src/mailmask.c)
target_include_directories(mailmask PRIVATE ${Milter_INCLUDE_DIRS} ${MYSQL_INCLUDE_DIR} ${LIBCONFIG_INCLUDE_DIR})
target_link_libraries(mailmask ${Milter_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${MYSQL_LIBRARY} ${LIBCONFIG_LIBRARIES})

install(TARGETS mailmask DESTINATION bin)
if(NOT WIN32 AND WITH_SYSTEMD)
	configure_file(systemd/mailmask.service.in ${CMAKE_CURRENT_BINARY_DIR}/systemd/mailmask.service)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/mailmask.service DESTINATION ${SYSTEMD_UNITDIR})
	install(FILES config/mailmask.conf DESTINATION ${CONFIG_DIR})
endif()
