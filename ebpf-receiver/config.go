package ebpf_receiver

// EbpfRcvrConfig represents the receiver config settings within the collector's config.yaml
type EbpfRcvrConfig struct {
	EbpfBinPath string `mapstructure:"ebpf_binary_path"`
	NicName     string `mapstructure:"nic_name"`
	IpFilter    string `mapstructure:"ip_filter"`
	PromiscMode bool   `mapstructure:"promisc_mode"`
}

// Validate checks if the receiver configuration is valid
func (cfg *EbpfRcvrConfig) Validate() error {
	if len(cfg.EbpfBinPath) == 0 || len(cfg.NicName) == 0 {
		Logger().Sugar().Fatalf("Both the ebpf_binary_path and the nic_name should be provided!")
	}
	return nil
}
