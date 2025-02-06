package pg_exporter

// PgExporterConfig defines configuration for debug exporter.
type PgExporterConfig struct {
	DSN           string `mapstructure:"dsn"`
	DbInitSqlPath string `mapstructure:"db_init_sql_path"`
}

// Validate checks if the exporter configuration is valid
func (cfg *PgExporterConfig) Validate() error {
	return nil
}
