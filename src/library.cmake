macro (LIBRARY name)
	set(ver_major ${${name}_VERSION_MAJOR})
	set(ver_minor ${${name}_VERSION_MINOR})
	set(ver_patch ${${name}_VERSION_PATCH})
	set(source ${${name}_SOURCE})
	set(ver_string ${ver_major}.${ver_minor}.${ver_patch})
	set(version_script ${CMAKE_CURRENT_SOURCE_DIR}/lib${name}.map)

	add_library(${name}-obj OBJECT ${source})

	target_include_directories(${name}-obj PUBLIC ../include)
	target_include_directories(${name}-obj PRIVATE ../common)

	target_compile_options(${name}-obj PRIVATE ${${name}_CFLAGS})
	target_compile_options(${name}-obj PRIVATE -pthread)
	target_compile_options(${name}-obj PRIVATE -fno-common)
	target_compile_options(${name}-obj PRIVATE -fPIC)

	# Shared library
	add_library(${name}-shared SHARED $<TARGET_OBJECTS:${name}-obj>)
	set_target_properties(${name}-shared
		PROPERTIES OUTPUT_NAME ${name})
	set_target_properties(${name}-shared
		PROPERTIES VERSION ${ver_string} SOVERSION ${ver_major})

	set_target_properties(${name}-shared
		PROPERTIES LINK_FLAGS "-Wl,--version-script=${version_script} -Wl,-z,relro -Wl,--fatal-warnings -Wl,--warn-common")

	add_library(${name}-static STATIC $<TARGET_OBJECTS:${name}-obj>)

	set_target_properties(${name}-static
		PROPERTIES OUTPUT_NAME ${name}_unscoped)

	add_custom_command(TARGET ${name}-static POST_BUILD
		COMMAND objcopy --localize-hidden `sed -n "'s/^\\s*\\([a-zA-Z0-9_]*\\);$$/-G \\1/p'" ${version_script}` lib${name}_unscoped.a lib${name}.a
		DEPENDS ${name}-static-unscoped)

	# Install targets
	install(TARGETS ${name}-shared LIBRARY
		CONFIGURATIONS Release
		DESTINATION lib
		PERMISSIONS
			OWNER_READ OWNER_WRITE OWNER_EXECUTE
			GROUP_READ GROUP_EXECUTE
			WORLD_READ WORLD_EXECUTE
	)
	install(TARGETS ${name}-shared LIBRARY
		CONFIGURATIONS Debug
		DESTINATION lib/nvml_debug
		PERMISSIONS
			OWNER_READ OWNER_WRITE OWNER_EXECUTE
			GROUP_READ GROUP_EXECUTE
			WORLD_READ WORLD_EXECUTE
	)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.a
		CONFIGURATIONS Release
		DESTINATION lib
		PERMISSIONS
			OWNER_READ OWNER_WRITE OWNER_EXECUTE
			GROUP_READ GROUP_EXECUTE
			WORLD_READ WORLD_EXECUTE
	)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.a
		CONFIGURATIONS Debug
		DESTINATION lib/nvml_debug
		PERMISSIONS
			OWNER_READ OWNER_WRITE OWNER_EXECUTE
			GROUP_READ GROUP_EXECUTE
			WORLD_READ WORLD_EXECUTE
	)
	install(FILES ${${name}_HEADERS}
		CONFIGURATIONS Debug Release
		DESTINATION include
		PERMISSIONS
			OWNER_READ OWNER_WRITE
			GROUP_READ
			WORLD_READ
	)
endmacro (LIBRARY)
