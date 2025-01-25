package ebpf_receiver

import (
	"go.uber.org/zap"
)

// EbpfRcvrConfig represents the receiver config settings within the collector's config.yaml
type EbpfRcvrConfig struct {
	EbpfBinPath string `mapstructure:"ebpf_binary_path"`
	NicName     string `mapstructure:"nic_name"`
	logger      *zap.Logger
}

// Validate checks if the receiver configuration is valid
func (cfg *EbpfRcvrConfig) Validate() error {
	if len(cfg.EbpfBinPath) == 0 || len(cfg.NicName) == 0 {
		cfg.logger.Sugar().Fatalf("Both the ebpf_binary_path and the nic_name should be provided!")
	}
	return nil
}
