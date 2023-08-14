CMAKE_MINIMUM_REQUIRED(VERSION 3.6.3)
PROJECT(libmoon C CXX)

find_package(PkgConfig REQUIRED)

option(USE_MLX5 "Compile with mlx5 driver" OFF)
option(USE_MLX4 "Compile with mlx4 driver" OFF)

SET(CMAKE_CXX_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu++11 -march=native -msse4.2")
SET(CMAKE_C_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -march=native -msse4.2")
SET(CMAKE_EXE_LINKER_FLAGS "-rdynamic") # to access functions from luajit

SET(FILES
	src/main.cpp
	src/memory.c
	src/task.cpp
	src/device.c
	src/i40e.c
	src/util.c
	src/lifecycle.cpp
	src/barrier.cpp
	src/task-results.cpp
	src/pipe.cpp
	src/lock.cpp
	src/namespaces.cpp
	src/ring.c
	src/filter.c
	src/pcap.cpp
	src/timestamping.c
	src/timestamping_i40e.c
	src/timestamping_ixgbe.c
	src/timestamping_igb.c
	src/bytesizedring.cpp
	src/pktsizedring.cpp
)

# SET(DPDK_LIBS
# 	rte_net      rte_ethdev       rte_distributor 	 rte_mbuf      rte_pmd_bond       rte_kni              rte_pmd_ring     rte_power  
# 	rte_acl      rte_eal          rte_kvargs   	 rte_mempool   rte_mempool_ring	  rte_pmd_e1000        rte_pmd_virtio   rte_ring
# 	rte_cfgfile  rte_hash         rte_lpm      	 rte_meter     rte_pmd_i40e   	  *rte_pmd_vmxnet3_uio  rte_sched        rte_timer
# 	rte_cmdline  rte_ip_frag      rte_pipeline 	 rte_pmd_ixgbe rte_mempool_stack  rte_port             rte_table        rte_pmd_bnxt
# 	rte_pmd_ena  rte_pmd_nfp      rte_stack          rte_bus_vdev  rte_bus_pci        rte_pci              rte_cryptodev
# )

# SET(DPDK_LIBS
# 	rte_net      rte_ethdev       rte_distributor 	 rte_mbuf      rte_pmd_bond       rte_kni              rte_pmd_ring     rte_power  
# 	rte_acl      rte_eal          rte_kvargs   	 rte_mempool   rte_mempool_ring	  rte_pmd_e1000        rte_pmd_virtio   rte_ring
# 	rte_cfgfile  rte_hash         rte_lpm      	 rte_meter     rte_pmd_i40e     rte_sched        rte_timer
# 	rte_cmdline  rte_ip_frag      rte_pipeline 	 rte_pmd_ixgbe rte_mempool_stack  rte_port             rte_table        rte_pmd_bnxt
# 	rte_pmd_ena  rte_pmd_nfp      rte_stack          rte_bus_vdev  rte_bus_pci        rte_pci              rte_cryptodev
# )

#Add Mellanox libraries if options are specified
if(USE_MLX5 OR USE_MLX4)
	SET(DPDK_LIBS ${DPDK_LIBS} ibverbs)
endif()

if(USE_MLX5)
	SET(DPDK_LIBS ${DPDK_LIBS} rte_pmd_mlx5)
endif()

if(USE_MLX4)
	SET(DPDK_LIBS ${DPDK_LIBS} rte_pmd_mlx4)
endif()

set(CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/lib-build/dpdk;${CMAKE_CURRENT_SOURCE_DIR}/lib-build/luajit;${CMAKE_CURRENT_SOURCE_DIR}/lib-build/tbb")
pkg_search_module(PKG_DPDK REQUIRED IMPORTED_TARGET libdpdk)
pkg_search_module(PKG_LUAJIT REQUIRED IMPORTED_TARGET luajit)
pkg_search_module(PKG_TBB REQUIRED IMPORTED_TARGET tbb)

# SET(LUAJIT_LIBS
# 	luajit-5.1
# )

SET(HIGHWAYHASH_LIBS
	highwayhash
)

# add tbb
# include(${CMAKE_CURRENT_SOURCE_DIR}/deps/tbb/cmake/TBBBuild.cmake)
# tbb_build(TBB_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/deps/tbb CONFIG_DIR TBB_DIR)
# find the cmake configuration file
# set(TBB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib-build/tbb/lib/cmake/TBB)
# find_package(TBB)

SET(ALL_LIBS
	-Wl,--whole-archive
	# ${LUAJIT_LIBS}
	${HIGHWAYHASH_LIBS}
	# ${TBB_IMPORTED_TARGETS}
	-Wl,--start-group ${DPDK_LIBS} numa -Wl,--end-group
	pthread dl rt
	-Wl,--no-whole-archive
	PkgConfig::PKG_DPDK
	PkgConfig::PKG_LUAJIT
	PkgConfig::PKG_TBB
)

INCLUDE_DIRECTORIES(
	# ${CMAKE_CURRENT_SOURCE_DIR}/lib-build/dpdk/include
	${CMAKE_CURRENT_SOURCE_DIR}/deps/dpdk/drivers/net/bnxt
	${CMAKE_CURRENT_SOURCE_DIR}/deps/dpdk/drivers/net/ixgbe/base
	${CMAKE_CURRENT_SOURCE_DIR}/deps/dpdk/drivers/net/ixgbe
	${CMAKE_CURRENT_SOURCE_DIR}/deps/dpdk/drivers/net/i40e/base
	${CMAKE_CURRENT_SOURCE_DIR}/deps/dpdk/drivers/net/i40e
	${CMAKE_CURRENT_SOURCE_DIR}/deps/dpdk/drivers/net/e1000
	${CMAKE_CURRENT_SOURCE_DIR}/deps/dpdk/drivers/net/e1000/base
	${PKG_DPDK_INCLUDE_DIRS}
	${PKG_LUAJIT_INCLUDE_DIRS}
	# ${CMAKE_CURRENT_SOURCE_DIR}/lib-build/luajit/usr/local/include
	${CMAKE_CURRENT_SOURCE_DIR}/deps/highwayhash/highwayhash
	# ${CMAKE_CURRENT_SOURCE_DIR}/lib-build/tbb/include
	${PKG_TBB_INCLUDE_DIRS}
	${CMAKE_CURRENT_SOURCE_DIR}/lib
	${CMAKE_CURRENT_SOURCE_DIR}/src
)

LINK_DIRECTORIES(
	# ${CMAKE_CURRENT_SOURCE_DIR}/lib-build/dpdk/lib/x86-64-linux-gnu
	# ${CMAKE_CURRENT_SOURCE_DIR}/lib-build/luajit/usr/local/lib
	${CMAKE_CURRENT_SOURCE_DIR}/deps/highwayhash/lib
)

IF(LIBMOON_BUILD_LIBRARY)
	ADD_DEFINITIONS(-DLIBMOON_BUILD_LIB)
	# we want libmoon.a, not liblibmoon.a
	ADD_LIBRARY(moon STATIC ${FILES})
	TARGET_LINK_LIBRARIES(moon ${ALL_LIBS})
ELSE()
	ADD_EXECUTABLE(libmoon ${FILES})
	TARGET_LINK_LIBRARIES(libmoon ${ALL_LIBS})
ENDIF()

