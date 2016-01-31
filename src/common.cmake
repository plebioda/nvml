include(CheckCCompilerFlag)
include(CheckCSourceCompiles)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSRCVERSION=\\\"${SRCVERSION}\\\"")
set(CMAKE_C_FLAGS_DEBUG "-ggdb -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpointer-arith")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-macros")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-field-initializers")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsign-conversion")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsign-compare")

set(SAFE_CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "-Wconversion")

check_c_source_compiles("long int random(void); char test(void); char test(void) { char a = 0; char b = 'a'; char ret = random() == 1 ? a : b; return ret; } int main() { return 0; }" HAS_WORKING_Wconversion)

set(CMAKE_REQUIRED_FLAGS "${SAFE_CMAKE_REQUIRED_FLAGS}")

if(HAS_WORKING_Wconversion)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion")
endif()

check_c_compiler_flag(-Wunreachable-code-return HAS_Wunreachable-code-return)
if(HAS_Wunreachable-code-return)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunreachable-code-return")
endif()

check_c_compiler_flag(-Wmissing-variable-declarations HAS_Wmissing-variable-declarations)
if(HAS_Wmissing-variable-declarations)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-variable-declarations")
endif()
