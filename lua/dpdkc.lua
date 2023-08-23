---------------------------------
--- @file dpdkc.lua
--- @brief DPDKc ...
--- @todo TODO docu
---------------------------------

--- low-level dpdk wrapper
local ffi = require "ffi"

-- structs
ffi.cdef[[
	// core management
	enum rte_lcore_state_t {
		WAIT, RUNNING, FINISHED
	};

	

	// packets/mbufs
	
	struct mempool {
	}; // dummy struct, only needed to associate it with a metatable

	typedef void    *RTE_MARKER[0];
	typedef void    *RTE_MARKER_CACHE_ALIGNED[0] __attribute__((aligned(64)));
	typedef uint8_t  RTE_MARKER8[0];
	typedef uint64_t RTE_MARKER64[0];

	static const uint8_t CHAR_BIT = 8;

	struct rte_mbuf_sched {
		uint32_t queue_id;   /**< Queue ID. */
		uint8_t traffic_class;
		/**< Traffic class ID. Traffic class 0
		 * is the highest priority traffic class.
		 */
		uint8_t color;
		/**< Color. @see enum rte_color.*/
		uint16_t reserved;   /**< Reserved. */
	}; /**< Hierarchical scheduler */

	struct rte_mbuf {
		RTE_MARKER cacheline0;
	
		void *buf_addr;           /**< Virtual address of segment buffer. */
		uint64_t buf_iova_or_next;
	
		/* next 8 bytes are initialised on RX descriptor rearm */
		RTE_MARKER64 rearm_data;
		uint16_t data_off;
	
		/**
		 * Reference counter. Its size should at least equal to the size
		 * of port field (16 bits), to support zero-copy broadcast.
		 * It should only be accessed using the following functions:
		 * rte_mbuf_refcnt_update(), rte_mbuf_refcnt_read(), and
		 * rte_mbuf_refcnt_set(). The functionality of these functions (atomic,
		 * or non-atomic) is controlled by the RTE_MBUF_REFCNT_ATOMIC flag.
		 */
		uint16_t refcnt;
	
		/**
		 * Number of segments. Only valid for the first segment of an mbuf
		 * chain.
		 */
		uint16_t nb_segs;
	
		/** Input port (16 bits to support more than 256 virtual ports).
		 * The event eth Tx adapter uses this field to specify the output port.
		 */
		uint16_t port;
	
		uint64_t ol_flags;        /**< Offload features. */
	
		/* remaining bytes are set on RX when pulling packet from descriptor */
		RTE_MARKER rx_descriptor_fields1;
	
		/*
		 * The packet type, which is the combination of outer/inner L2, L3, L4
		 * and tunnel types. The packet_type is about data really present in the
		 * mbuf. Example: if vlan stripping is enabled, a received vlan packet
		 * would have RTE_PTYPE_L2_ETHER and not RTE_PTYPE_L2_VLAN because the
		 * vlan is stripped from the data.
		 */

		union {
			uint32_t packet_type; /**< L2/L3/L4 and tunnel information. */

			struct {
				uint8_t l2_type:4;   /**< (Outer) L2 type. */
				uint8_t l3_type:4;   /**< (Outer) L3 type. */
				uint8_t l4_type:4;   /**< (Outer) L4 type. */
				uint8_t tun_type:4;  /**< Tunnel type. */

				union {
					uint8_t inner_esp_next_proto;
					/**< ESP next protocol type, valid if
					 * RTE_PTYPE_TUNNEL_ESP tunnel type is set
					 * on both Tx and Rx.
					 */

					struct {
						uint8_t inner_l2_type:4;
						/**< Inner L2 type. */
						uint8_t inner_l3_type:4;
						/**< Inner L3 type. */
					};
				};
				uint8_t inner_l4_type:4; /**< Inner L4 type. */
			};
		};
	
		uint32_t pkt_len;         /**< Total pkt len: sum of all segments. */
		uint16_t data_len;        /**< Amount of data in segment buffer. */
		/** VLAN TCI (CPU order), valid if RTE_MBUF_F_RX_VLAN is set. */
		uint16_t vlan_tci;
	

		union {
			union {
				uint32_t rss;     /**< RSS hash result if RSS enabled */
				struct {
					union {
						struct {
							uint16_t hash;
							uint16_t id;
						};
						uint32_t lo;
						/**< Second 4 flexible bytes */
					};
					uint32_t hi;
					/**< First 4 flexible bytes or FD ID, dependent
					 * on RTE_MBUF_F_RX_FDIR_* flag in ol_flags.
					 */
				} fdir;	/**< Filter identifier if FDIR enabled */
				struct rte_mbuf_sched sched;
				/**< Hierarchical scheduler : 8 bytes */
				struct {
					uint32_t reserved1;
					uint16_t reserved2;
					uint16_t txq;
					/**< The event eth Tx adapter uses this field
					 * to store Tx queue id.
					 * @see rte_event_eth_tx_adapter_txq_set()
					 */
				} txadapter; /**< Eventdev ethdev Tx adapter */
				uint32_t usr;
				/**< User defined tags. See rte_distributor_process() */
			} hash;                   /**< hash information */
		};
	
		/** Outer VLAN TCI (CPU order), valid if RTE_MBUF_F_RX_QINQ is set. */
		uint16_t vlan_tci_outer;
	
		uint16_t buf_len;         /**< Length of segment buffer. */
	
		struct rte_mempool *pool; /**< Pool from which mbuf was allocated. */
	
		/* second cache line - fields only used in slow path or on TX */
		RTE_MARKER cacheline1;
	
		uint64_t next_or_dynfield2;
	
		/* fields to support TX offloads */

		union {
			uint64_t tx_offload;       /**< combined for easy fetch */

			// Removed bit indices because they're not supported in LuaJIT on uint64_t
			// https://github.com/LuaJIT/LuaJIT/issues/951
			struct {
				uint64_t l2_len;
				/**< L2 (MAC) Header Length for non-tunneling pkt.
				 * Outer_L4_len + ... + Inner_L2_len for tunneling pkt.
				 */
				uint64_t l3_len;
				/**< L3 (IP) Header Length. */
				uint64_t l4_len;
				/**< L4 (TCP/UDP) Header Length. */
				uint64_t tso_segsz;
				/**< TCP TSO segment size */
	
				/*
				 * Fields for Tx offloading of tunnels.
				 * These are undefined for packets which don't request
				 * any tunnel offloads (outer IP or UDP checksum,
				 * tunnel TSO).
				 *
				 * PMDs should not use these fields unconditionally
				 * when calculating offsets.
				 *
				 * Applications are expected to set appropriate tunnel
				 * offload flags when they fill in these fields.
				 */
				uint64_t outer_l3_len;
				/**< Outer L3 (IP) Hdr Length. */
				uint64_t outer_l2_len;
				/**< Outer L2 (MAC) Hdr Length. */
	
				/* uint64_t unused:RTE_MBUF_TXOFLD_UNUSED_BITS; */
			};
		};
	
		/** Shared data for external buffer attached to mbuf. See
		 * rte_pktmbuf_attach_extbuf().
		 */
		void *shinfo;
	
		/** Size of the application private data. In case of an indirect
		 * mbuf, it stores the direct mbuf private data size.
		 */
		uint16_t priv_size;
	
		/** Timesync flags for use with IEEE1588. */
		uint16_t timesync;
	
		uint32_t dynfield1[9]; /**< Reserved for dynamic fields. */
	};

	// device status/info
	struct rte_eth_link {
		uint32_t link_speed;
		uint16_t link_duplex: 1;
		uint16_t link_autoneg: 1;
		uint16_t link_status: 1;
	} __attribute__((__aligned__(8)));

	// Probably unused
	struct rte_fdir_filter {
		uint16_t flex_bytes;
		uint16_t vlan_id;
		uint16_t port_src;
		uint16_t port_dst;
		union {
			uint32_t ipv4_addr;
			uint32_t ipv6_addr[4];
		} ip_src;
		union {
			uint32_t ipv4_addr;
			uint32_t ipv6_addr[4];
		} ip_dst;
		int l4type;
		int iptype;
	};

	// Probably unused
	enum rte_l4type {
		RTE_FDIR_L4TYPE_NONE = 0,       /**< None. */
		RTE_FDIR_L4TYPE_UDP,            /**< UDP. */
		RTE_FDIR_L4TYPE_TCP,            /**< TCP. */
		RTE_FDIR_L4TYPE_SCTP,           /**< SCTP. */
	};


	// Probably unused
	struct rte_fdir_masks {
		uint8_t only_ip_flow;
		uint8_t vlan_id;
		uint8_t vlan_prio;
		uint8_t flexbytes;
		uint8_t set_ipv6_mask;
		uint8_t comp_ipv6_dst;
		uint32_t dst_ipv4_mask;
		uint32_t src_ipv4_mask;
		uint16_t dst_ipv6_mask;
		uint16_t src_ipv6_mask;
		uint16_t src_port_mask;
		uint16_t dst_port_mask;
	};

	struct rte_eth_desc_lim {
		uint16_t nb_max;   
		uint16_t nb_min;   
		uint16_t nb_align;
		uint16_t nb_seg_max;
		uint16_t nb_mtu_seg_max; 
	};
	struct rte_eth_thresh {
		uint8_t pthresh; 
		uint8_t hthresh; 
		uint8_t wthresh; 
	};
	struct rte_eth_switch_info {
		const char *name;	/**< switch name */
		uint16_t domain_id;	/**< switch domain ID */
		uint16_t port_id;
		uint16_t rx_domain;
	};
	struct rte_eth_dev_portconf {
		uint16_t burst_size; /**< Device-preferred burst size */
		uint16_t ring_size; /**< Device-preferred size of queue rings */
		uint16_t nb_queues; /**< Device-preferred number of queues */
	};
	struct rte_eth_rxconf {
		struct rte_eth_thresh rx_thresh; /**< Rx ring threshold registers. */
		uint16_t rx_free_thresh; /**< Drives the freeing of Rx descriptors. */
		uint8_t rx_drop_en; /**< Drop packets if no descriptors are available. */
		uint8_t rx_deferred_start; /**< Do not start queue with rte_eth_dev_start(). */
		uint16_t rx_nseg; /**< Number of descriptions in rx_seg array. */
		uint16_t share_group;
		uint16_t share_qid; /**< Shared Rx queue ID in group */
		uint64_t offloads;
		union rte_eth_rxseg *rx_seg;

		struct rte_mempool **rx_mempools;
		uint16_t rx_nmempool; /** < Number of Rx mempools */

		uint64_t reserved_64s[2]; /**< Reserved for future fields */
		void *reserved_ptrs[2];   /**< Reserved for future fields */
	};

	struct rte_eth_txconf {
		struct rte_eth_thresh tx_thresh; /**< Tx ring threshold registers. */
		uint16_t tx_rs_thresh; /**< Drives the setting of RS bit on TXDs. */
		uint16_t tx_free_thresh; /**< Start freeing Tx buffers if there are
						less free descriptors than this value. */

		uint8_t tx_deferred_start; /**< Do not start queue with rte_eth_dev_start(). */
		uint64_t offloads;

		uint64_t reserved_64s[2]; /**< Reserved for future fields */
		void *reserved_ptrs[2];   /**< Reserved for future fields */
	};

	struct rte_eth_dev_info {
		void *device; /**< Generic device information */
		const char *driver_name; /**< Device Driver name. */
		unsigned int if_index; /**< Index to bound host interface, or 0 if none.
			Use if_indextoname() to translate into an interface name. */
		uint16_t min_mtu;	/**< Minimum MTU allowed */
		uint16_t max_mtu;	/**< Maximum MTU allowed */
		const uint32_t *dev_flags; /**< Device flags */
		uint32_t min_rx_bufsize; /**< Minimum size of Rx buffer. */
		uint32_t max_rx_pktlen; /**< Maximum configurable length of Rx pkt. */
		/** Maximum configurable size of LRO aggregated packet. */
		uint32_t max_lro_pkt_size;
		uint16_t max_rx_queues; /**< Maximum number of Rx queues. */
		uint16_t max_tx_queues; /**< Maximum number of Tx queues. */
		uint32_t max_mac_addrs; /**< Maximum number of MAC addresses. */
		/** Maximum number of hash MAC addresses for MTA and UTA. */
		uint32_t max_hash_mac_addrs;
		uint16_t max_vfs; /**< Maximum number of VFs. */
		uint16_t max_vmdq_pools; /**< Maximum number of VMDq pools. */
		uint16_t rx_seg_capa[4]; /**< Segmentation capability.*/
		/** All Rx offload capabilities including all per-queue ones */
		uint64_t rx_offload_capa;
		/** All Tx offload capabilities including all per-queue ones */
		uint64_t tx_offload_capa;
		/** Device per-queue Rx offload capabilities. */
		uint64_t rx_queue_offload_capa;
		/** Device per-queue Tx offload capabilities. */
		uint64_t tx_queue_offload_capa;
		/** Device redirection table size, the total number of entries. */
		uint16_t reta_size;
		uint8_t hash_key_size; /**< Hash key size in bytes */
		/** Bit mask of RSS offloads, the bit offset also means flow type */
		uint64_t flow_type_rss_offloads;
		struct rte_eth_rxconf default_rxconf; /**< Default Rx configuration */
		struct rte_eth_txconf default_txconf; /**< Default Tx configuration */
		uint16_t vmdq_queue_base; /**< First queue ID for VMDq pools. */
		uint16_t vmdq_queue_num;  /**< Queue number for VMDq pools. */
		uint16_t vmdq_pool_base;  /**< First ID of VMDq pools. */
		struct rte_eth_desc_lim rx_desc_lim;  /**< Rx descriptors limits */
		struct rte_eth_desc_lim tx_desc_lim;  /**< Tx descriptors limits */
		uint32_t speed_capa;  /**< Supported speeds bitmap (RTE_ETH_LINK_SPEED_). */
		/** Configured number of Rx/Tx queues */
		uint16_t nb_rx_queues; /**< Number of Rx queues. */
		uint16_t nb_tx_queues; /**< Number of Tx queues. */
		/**
		* Maximum number of Rx mempools supported per Rx queue.
		*
		* Value greater than 0 means that the driver supports Rx queue
		* mempools specification via rx_conf->rx_mempools.
		*/
		uint16_t max_rx_mempools;
		/** Rx parameter recommendations */
		struct rte_eth_dev_portconf default_rxportconf;
		/** Tx parameter recommendations */
		struct rte_eth_dev_portconf default_txportconf;
		/** Generic device capabilities (RTE_ETH_DEV_CAPA_). */
		uint64_t dev_capa;
		/**
		* Switching information for ports on a device with a
		* embedded managed interconnect/switch.
		*/
		struct rte_eth_switch_info switch_info;
		/** Supported error handling mode. */
		int err_handle_mode;

		uint64_t reserved_64s[2]; /**< Reserved for future fields */
		void *reserved_ptrs[2];   /**< Reserved for future fields */
	};

	struct libmoon_device_config {
		uint32_t port;
		struct mempool** mempools;
		uint16_t rx_queues;
		uint16_t tx_queues;
		uint16_t rx_descs;
		uint16_t tx_descs;
		uint8_t drop_enable;
		uint8_t enable_rss;
		uint8_t disable_offloads;
		uint8_t strip_vlan;
		uint32_t rss_mask;
	};
]]

-- dpdk functions and wrappers
ffi.cdef[[
	// eal init
	int rte_eal_init(int argc, const char* argv[]); 
	
	// cpu core management
	int rte_eal_get_lcore_state(int core);
	enum rte_lcore_state_t rte_eal_get_lcore_state(unsigned int slave_id);
	int rte_eal_wait_lcore(int core);
	uint32_t rte_lcore_to_socket_id_export(uint32_t lcore_id);
	uint32_t get_current_core();
	uint32_t get_current_socket();

	// memory
	struct mempool* init_mem(uint32_t nb_mbuf, uint32_t sock, uint32_t mbuf_size);
	struct rte_mbuf* rte_pktmbuf_alloc_export(struct mempool* mp);
	void alloc_mbufs(struct mempool* mp, struct rte_mbuf* bufs[], uint32_t len, uint16_t pkt_len);
	void rte_pktmbuf_free_export(struct rte_mbuf* m);
	uint16_t rte_mbuf_refcnt_read_export(struct rte_mbuf* m);
	uint16_t rte_mbuf_refcnt_update_export(struct rte_mbuf* m, int16_t value);
	char *rte_pktmbuf_adj_export(struct rte_mbuf *m, uint16_t len);
	int rte_pktmbuf_trim_export(struct rte_mbuf *m, uint16_t len);

	// devices
	int rte_eth_dev_count_avail();
	uint64_t dpdk_get_mac_addr(int port, char* buf);
	void rte_eth_link_get(uint16_t port, struct rte_eth_link* link);
	void rte_eth_link_get_nowait(uint16_t port, struct rte_eth_link* link);
	int dpdk_configure_device(struct libmoon_device_config*);
	void get_mac_addr(int port, char* buf);
	uint32_t dpdk_get_pci_id(uint16_t port);
	uint32_t read_reg32(uint16_t port, uint32_t reg);
	uint64_t read_reg64(uint16_t port, uint32_t reg);
	void write_reg32(uint16_t port, uint32_t reg, uint32_t val);
	void write_reg64(uint16_t port, uint32_t reg, uint64_t val);
	void rte_eth_promiscuous_enable(uint16_t port);
	void rte_eth_promiscuous_disable(uint16_t port);
	uint8_t dpdk_get_socket(uint8_t port);
	// void* dpdk_get_eth_dev(int port);
	void* dpdk_get_i40e_dev(int port);
	int dpdk_get_i40e_vsi_seid(int port);
	// uint8_t dpdk_get_pci_function(uint8_t port);
	int dpdk_get_max_ports();
	int rte_eth_dev_mac_addr_add(uint16_t port, struct rte_ether_addr* mac, uint32_t pool);
	int rte_eth_dev_mac_addr_remove(uint16_t port, struct rte_ether_addr* mac);
	void rte_eth_macaddr_get(uint16_t port_id, struct rte_ether_addr* mac_addr);
	int rte_eth_set_queue_rate_limit(uint16_t port_idx, uint16_t queue_idx, uint32_t tx_rate);
	void rte_eth_dev_info_get(uint16_t port_id, struct rte_eth_dev_info* dev_info);
	void rte_eth_dev_stop(uint16_t port_id);
	int rte_eth_dev_fw_version_get(uint16_t port_id, char* fw_version, size_t fw_size);

	// rx & tx
	uint16_t rte_eth_rx_burst_export(uint16_t port_id, uint16_t queue_id, struct rte_mbuf** rx_pkts, uint16_t nb_pkts);
	uint16_t rte_eth_tx_burst_export(uint16_t port_id, uint16_t queue_id, struct rte_mbuf** tx_pkts, uint16_t nb_pkts);
	uint16_t rte_eth_tx_prepare_export(uint16_t port_id, uint16_t queue_id, struct rte_mbuf** tx_pkts, uint16_t nb_pkts);
	int rte_eth_dev_tx_queue_start(uint16_t port_id, uint16_t rx_queue_id);
	int rte_eth_dev_tx_queue_stop(uint16_t port_id, uint16_t rx_queue_id);
	void dpdk_send_all_packets(uint16_t port_id, uint16_t queue_id, struct rte_mbuf** pkts, uint16_t num_pkts);
	void dpdk_send_single_packet(uint16_t port_id, uint16_t queue_id, struct rte_mbuf* pkt);
	uint16_t dpdk_try_send_single_packet(uint16_t port_id, uint16_t queue_id, struct rte_mbuf* pkt);

	// stats
	uint32_t dpdk_get_rte_queue_stat_cntrs_num();
	int rte_eth_stats_get(uint16_t port_id, struct rte_eth_stats* stats);
	
	// checksum offloading
	void calc_ipv4_pseudo_header_checksum(void* data, int offset);
	void calc_ipv4_pseudo_header_checksums(struct rte_mbuf** pkts, uint16_t num_pkts, int offset);
	void calc_ipv6_pseudo_header_checksum(void* data, int offset);
	void calc_ipv6_pseudo_header_checksums(struct rte_mbuf** pkts, uint16_t num_pkts, int offset);

	// timers
	void rte_delay_ms_export(uint32_t ms);
	void rte_delay_us_export(uint32_t us);
	uint64_t read_rdtsc();
	uint64_t rte_get_tsc_hz();

	// lifecycle
	uint8_t is_running(uint32_t extra_time);
	void set_runtime(uint32_t ms);

	// timestamping
	uint16_t dpdk_receive_with_timestamps_software(uint16_t port_id, uint16_t queue_id, struct rte_mbuf** rx_pkts, uint16_t nb_pkts);
	int rte_eth_timesync_enable(uint16_t port_id);
	int rte_eth_timesync_read_tx_timestamp(uint16_t port_id, struct timespec* timestamp);
	int rte_eth_timesync_read_rx_timestamp(uint16_t port_id, struct timespec* timestamp, uint32_t timesync);
	int rte_eth_timesync_read_time(uint16_t port_id, struct timespec* time);
	void libmoon_sync_clocks(uint8_t port1, uint8_t port2, uint32_t timl, uint32_t timh, uint32_t adjl, uint32_t adjh);
]]

return ffi.C

