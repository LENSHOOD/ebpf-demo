module github.com/open-telemetry/otelcol-ebpf-demo/pg-exporter

go 1.23.4

require (
	github.com/jackc/pgx/v4 v4.18.3
	go.opentelemetry.io/collector/component v0.119.0
	go.opentelemetry.io/collector/consumer v1.25.0
	go.opentelemetry.io/collector/exporter v0.119.0
	go.opentelemetry.io/collector/exporter/xexporter v0.119.0
	go.opentelemetry.io/collector/pdata v1.25.0
	go.uber.org/zap v1.27.0
)

require (
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.14.3 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgtype v1.14.0 // indirect
	github.com/jackc/puddle v1.3.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	go.opentelemetry.io/collector/config/configretry v1.23.0 // indirect
	go.opentelemetry.io/collector/config/configtelemetry v0.117.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.117.0 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.117.0 // indirect
	go.opentelemetry.io/collector/extension v0.117.0 // indirect
	go.opentelemetry.io/collector/extension/xextension v0.117.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.23.0 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.117.0 // indirect
	go.opentelemetry.io/collector/pipeline v0.117.0 // indirect
	go.opentelemetry.io/otel v1.32.0 // indirect
	go.opentelemetry.io/otel/metric v1.32.0 // indirect
	go.opentelemetry.io/otel/sdk v1.32.0 // indirect
	go.opentelemetry.io/otel/trace v1.32.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/grpc v1.69.2 // indirect
	google.golang.org/protobuf v1.36.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace google.golang.org/genproto => google.golang.org/genproto v0.0.0-20241104194629-dd2ea8efbc28
