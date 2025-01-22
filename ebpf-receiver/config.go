package ebpf_receiver

// EbpfRcvrConfig represents the receiver config settings within the collector's config.yaml
type EbpfRcvrConfig struct{}

// Validate checks if the receiver configuration is valid
func (cfg *EbpfRcvrConfig) Validate() error {
	return nil
}
