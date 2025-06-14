package ebpf_receiver

import (
	"context"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
)

var (
	typeStr    = component.MustNewType("ebpf_receiver")
	logger     *zap.Logger
	loggerOnce sync.Once
)

func createDefaultConfig() component.Config {
	return &EbpfRcvrConfig{}
}

func createTracesReceiver(_ context.Context, params receiver.Settings, baseCfg component.Config, consumer consumer.Traces) (receiver.Traces, error) {

	log := params.Logger
	cfg := baseCfg.(*EbpfRcvrConfig)

	loggerOnce.Do(func() { logger = log })
	traceRcvr := &ebpfReceiver{
		nextConsumer: consumer,
		config:       cfg,
		esf: &EbpfSocketFilter{
			objs: &EsfObjects{},
		},
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

func Logger() *zap.Logger {
	if logger == nil {
		panic("Logger used before initialization!")
	}
	return logger
}
