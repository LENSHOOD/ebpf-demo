package ebpf_receiver

// EbpfRcvrConfig represents the receiver config settings within the collector's config.yaml
type EbpfRcvrConfig struct {
	EbpfTrafficBinPath string `mapstructure:"ebpf_traffic_binary_path"`
	EbpfPidBinPath     string `mapstructure:"ebpf_pid_binary_path"`
	EbpfFileRwBinPath  string `mapstructure:"ebpf_file_rw_binary_path"`
	NicName            string `mapstructure:"nic_name"`
	IpFilter           string `mapstructure:"ip_filter"`
	PromiscMode        bool   `mapstructure:"promisc_mode"`
	DebugMode          bool   `mapstructure:"debug_mode"`
}

// Validate checks if the receiver configuration is valid
func (cfg *EbpfRcvrConfig) Validate() error {
	if len(cfg.EbpfTrafficBinPath) == 0 {
		Logger().Sugar().Fatalf("the ebpf_traffic_binary_path should be provided!")
	}

	if len(cfg.NicName) == 0 {
		Logger().Sugar().Fatalf("the nic_name should be provided!")
	}

	if len(cfg.EbpfPidBinPath) == 0 {
		Logger().Sugar().Fatalf("the ebpf_pid_binary_path should be provided!")
	}

	if len(cfg.EbpfFileRwBinPath) == 0 {
		Logger().Sugar().Fatalf("the ebpf_file_rw_binary_path should be provided!")
	}
	return nil
}
