package pg_exporter

import (
	"context"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/xexporter"
)

// The value of "type" key in configuration.
var typeStr = component.MustNewType("pg_exporter")

// NewFactory creates a factory for Debug exporter
func NewFactory() exporter.Factory {
	return xexporter.NewFactory(
		typeStr,
		createDefaultConfig,
		xexporter.WithTraces(createTraces, component.StabilityLevelAlpha),
	)
}

func createDefaultConfig() component.Config {
	return &PgExporterConfig{}
}

func createTraces(ctx context.Context, settings exporter.Settings, config component.Config) (exporter.Traces, error) {
	cfg := config.(*PgExporterConfig)
	logger := settings.Logger
	pgExporter, err := newPgExporter(cfg, logger)
	if err != nil {
		logger.Sugar().Fatalf("Connectg PG error: %v", err)
	}
	return exporterhelper.NewTraces(ctx, settings, config,
		pgExporter.pushTraces,
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
		exporterhelper.WithTimeout(exporterhelper.TimeoutConfig{Timeout: 0}),
		exporterhelper.WithShutdown(pgExporter.Shutdown),
	)
}
