SHELL := /bin/bash

# Build directory for libmoon
build_dir := build
num_cpus = $(shell cat /proc/cpuinfo  | grep "processor\\s: " | wc -l)

.PHONY build-dep:
build-dep:
	@echo "Building and installing libmoon dependencies..."
	git submodule update --init --recursive

	@echo "Building LuaJIT"
	cd deps/luajit && \
	$(MAKE) -j $(num_cpus) 'CFLAGS=-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT' && \
	sudo $(MAKE) install

	@echo "Building DPDK"
	cd deps/dpdk && \
	meson setup -Denable_driver_sdk=true build && \
	cd build && \
	meson compile && \
	sudo meson install && \
	sudo ldconfig

	@echo "Building turbo"
	@cd lua/lib/turbo && \
	( \
	$(MAKE) 2> /dev/null; \
	if [[ $$? > 0 ]]; then \
		echo "Could not compile Turbo with TLS support, disabling TLS"; \
		echo "Install libssl-dev and OpenSSL to enable TLS support"; \
		$(MAKE) SSL=none; \
	fi \
	)

# Allow fail of make install because highwayhash will error if it was installed previously
	@echo "Building Highwayhash"
	cd deps/highwayhash && \
	$(MAKE) && \
	(sudo $(MAKE) install || true)

	@echo "Building oneTBB"
	mkdir -p deps/tbb/build
	cd deps/tbb/build && \
	cmake -DTBB_TEST=OFF -S .. -B . && \
	cmake --build . -j $(num_cpus) && \
	sudo cmake --install .

	@echo "Successfully built libmoon dependencies"

.PHONY: build
build:
	@echo "Building libmoon..."
	meson setup $(build_dir)
	cd $(build_dir) && \
	meson compile
	@echo "Successfully built libmoon"

.PHONY: install
install:
	@echo "Installing libmoon..."
	cd $(build_dir) && \
	sudo meson install
	@echo "Successfully installed libmoon"

.PHONY: uninstall
uninstall:
	@echo "Uninstallung libmoon and all dependencies"

	cd deps/luajit && \
	sudo $(MAKE) uninstall || true

	cd deps/dpdk/build && \
	sudo ninja uninstall && \
	sudo ldconfig || true

# Manually uninstall highwayhash since they don#t provide a script for that
	cd /usr/local/lib && \
	sudo rm -rf libhighwayhash.*

	sudo rm -rf /usr/local/include/highwayhash

# Hopefully deletes all oneTBB files
	xargs rm -rf < deps/tbb/build/install_manifest.txt || true

# Uninstall libmoon
	cd $(build_dir) && \
	sudo ninja uninstall || true

	@echo "Uninstalled libmoon and all dependencies"

.PHONY: clean
clean: ## Clean the build directory of libmoon, not the dependencies (this does NOT delete all build files, use wipe for this)
	@echo "Cleaning up build files of libmoon..."
	cd $(build_dir) && meson compile --clean || true

.PHONY: wipe
wipe: ## Deletes all build files of libmoon (not the dependencies)
	@echo "Wiping build files of libmoon..."
	rm -rf $(build_dir)

.PHONY: clean-all
clean-all: clean ## Clean the build directory of libmoon and dependencies (this does NOT delete all build files, use wipe for this)
	@echo "Cleaning build files of libmoon and dependencies..."

	cd deps/luajit && \
	$(MAKE) clean || true

	cd deps/dpdk/build && \
	meson compile --clean || true

	cd lua/lib/turbo && \
	$(MAKE) clean || true

	cd deps/highwayhash && \
	$(MAKE) clean || true

	rm -rf deps/tbb/build

.PHONY: wipe-all
wipe-all: wipe ## Deletes all build files (of libmoon and dependencies)
	@echo "Wiping build files of libmoon and dependencies..."

	cd deps/luajit && \
	$(MAKE) clean || true

	rm -rf deps/dpdk/build

	cd lua/lib/turbo && \
	$(MAKE) clean || true

	cd deps/highwayhash && \
	$(MAKE) distclean || true

	rm -rf deps/tbb/build
