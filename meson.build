project(
    'libmoon',
    'c',
    'cpp',
    version: '1.0.0'
)

pkg = import('pkgconfig')
cxx = meson.get_compiler('cpp')

src_files = [
    'src/main.cpp',
    'src/memory.c',
    'src/task.cpp',
    'src/device.c',
    'src/i40e.c',
    'src/util.c',
    'src/lifecycle.cpp',
    'src/barrier.cpp',
    'src/task-results.cpp',
    'src/pipe.cpp',
    'src/lock.cpp',
    'src/namespaces.cpp',
    'src/ring.c',
    'src/filter.c',
    'src/pcap.cpp',
    'src/timestamping.c',
    'src/timestamping_i40e.c',
    'src/timestamping_ixgbe.c',
    'src/timestamping_igb.c',
    'src/bytesizedring.cpp',
    'src/pktsizedring.cpp'
]

header_files = [
    'src/bytesizedring.hpp',
    'src/config.h',
    'src/device.h',
    'src/lifecycle.h',
    'src/lifecycle.hpp',
    'src/main.hpp',
    'src/memory.h',
    'src/pktsizedring.hpp',
    'src/rdtsc.h',
    'src/ring.h',
    'src/task.hpp',
    'src/timestamping.h'
]

header_files_concurrentqueue = [
    'lib/concurrentqueue/concurrentqueue.h'
]

header_files_spsc_queue = [
    'lib/spsc-queue/atomicops.h',
    'lib/spsc-queue/readerwriterqueue.h'
]

# Additional DPDK includes
dep_dpdk_additional_includes = include_directories([
    './deps/dpdk/drivers/net/bnxt',
    './deps/dpdk/drivers/net/ixgbe/base',
    './deps/dpdk/drivers/net/ixgbe',
    './deps/dpdk/drivers/net/i40e/base',
    './deps/dpdk/drivers/net/i40e',
    './deps/dpdk/drivers/net/e1000',
    './deps/dpdk/drivers/net/e1000/base'
])
dep_dpdk_additional = declare_dependency(
    include_directories: dep_dpdk_additional_includes
)
dep_dpdk = dependency('libdpdk', version: '=23.07.0')
dep_luajit = dependency('luajit', version: '=2.1.0-beta3')
dep_tbb = dependency('tbb', version: '=2021.10.0')

dep_highwayhash_cxx = cxx.find_library(
    'highwayhash',
    dirs: ['/usr/local/lib']
)
dep_highwayhash = declare_dependency(
    include_directories: include_directories(['/usr/local/include/highwayhash']),
    dependencies: dep_highwayhash_cxx
)

dep_lib_includes = include_directories(['./lib/'])
dep_lib = declare_dependency(
    include_directories: dep_lib_includes
)

dependencies = [
    dep_dpdk,
    dep_dpdk_additional,
    dep_luajit,
    dep_tbb,
    dep_highwayhash,
    dep_lib
]

# executable('moon', src_files, dependencies: dependencies)
library(
    'moon',
    src_files,
    dependencies: dependencies,
    # Export all (not only used) symbols so that LuaJIT can access them
    link_args: ['-rdynamic'],
    cpp_args: ['-std=c++11'],
    install: true,
)

install_headers(header_files, subdir: 'libmoon')
install_headers(header_files_concurrentqueue, subdir: 'concurrentqueue')
install_headers(header_files_spsc_queue, subdir: 'spsc_queue')

pkg.generate(
    name: 'libmoon',
    filebase: 'libmoon',
    description: 'Libmoon library used for the MoonGen traffic generator',
    subdirs: ['libmoon'],
    libraries: ['-L${libdir}', '-llibmoon']
)
