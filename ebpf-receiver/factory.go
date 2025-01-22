package ebpf_receiver

import (
	"context"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

var (
	typeStr = component.MustNewType("ebpf_receiver")
)

func createDefaultConfig() component.Config {
	return &EbpfRcvrConfig{}
}

func createTracesReceiver(_ context.Context, params receiver.Settings, baseCfg component.Config, consumer consumer.Traces) (receiver.Traces, error) {

	logger := params.Logger
	cfg := baseCfg.(*EbpfRcvrConfig)

	traceRcvr := &ebpfReceiver{
		logger:       logger,
		nextConsumer: consumer,
		config:       cfg,
		objs:         &BPFObjects{},
	}

	return traceRcvr, nil
}

// NewFactory creates a factory for ebpf receiver.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		typeStr,
		createDefaultConfig,
		receiver.WithTraces(createTracesReceiver, component.StabilityLevelAlpha))
}
