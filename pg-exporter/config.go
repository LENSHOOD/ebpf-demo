package pg_exporter

// PgExporterConfig defines configuration for debug exporter.
type PgExporterConfig struct {
	DSN string `mapstructure:"dsn"`
}

// Validate checks if the exporter configuration is valid
func (cfg *PgExporterConfig) Validate() error {
	return nil
}
