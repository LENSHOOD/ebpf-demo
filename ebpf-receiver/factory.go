package ebpf_receiver

import (
	"context"
	"runtime"
	"sync"
	"time"

	"net/http"
	_ "net/http/pprof"

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

	if cfg.DebugMode {
		startPprof()
	}

	loggerOnce.Do(func() { logger = log })
	traceRcvr := &ebpfReceiver{
		nextConsumer: consumer,
		config:       cfg,
		esf: &EbpfSocketFilter{
			objs: &EsfObjects{},
		},
		eqtp: &EbpfQuadTuplePid{
			objs: &EqtpObjects{},
		},
	}

	return traceRcvr, nil
}

func startPprof() {
	go func() {
        http.ListenAndServe("0.0.0.0:6060", nil)
    }()

	go func ()  {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C{
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			Logger().Sugar().Errorf(
				"\nSys = %v MiB\nHeapAlloc = %v MiB\nHeapInuse = %v MiB\nHeapSys = %v MiB\nObjects = %v\nHeapIdle = %v MiB\nHeapReleased = %v MiB\n", 
				mem.Sys/1024/1024, 
				mem.HeapAlloc/1024/1024, 
				mem.HeapInuse/1024/1024, 
				mem.HeapSys/1024/1024, 
				mem.HeapObjects, 
				mem.HeapIdle/1024/1024, 
				mem.HeapReleased/1024/1024)
		}
	}()
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
