package pg_exporter

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4/pgxpool"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

type postgresExporter struct {
	logger *zap.Logger
	pool   *pgxpool.Pool
}

func newPgExporter(cfg *PgExporterConfig, logger *zap.Logger) (*postgresExporter, error) {
	pool, err := pgxpool.Connect(context.Background(), cfg.DSN)
	if err != nil {
		return nil, err
	}
	return &postgresExporter{logger: logger, pool: pool}, nil
}

func (e *postgresExporter) pushTraces(ctx context.Context, td ptrace.Traces) error {
	resourceSpans := td.ResourceSpans()
	for i := 0; i < resourceSpans.Len(); i++ {
		resourceSpan := resourceSpans.At(i)
		rs := resourceSpan.Resource()
		srcIp, _ := rs.Attributes().Get("src.ip")
		destIp, _ := rs.Attributes().Get("dest.ip")
		destPort, _ := rs.Attributes().Get("dest.port")
		_ = e.insertGraph(ctx, srcIp.AsString(), destIp.AsString(), destPort.Int())
	}
	return nil
}

func (e *postgresExporter) insertGraph(ctx context.Context, srcIp string, destIp string, destPort int64) error {
	if err := e.insertNode(ctx, srcIp); err != nil {
		return fmt.Errorf("failed to insert srcIp into nodes: %w", err)
	}

	if err := e.insertNode(ctx, destIp); err != nil {
		return fmt.Errorf("failed to insert destIp into nodes: %w", err)
	}

	if err := e.insertEdge(ctx, srcIp, destIp); err != nil {
		return fmt.Errorf("failed to insert edge into edges: %w", err)
	}

	return nil
}

func (e *postgresExporter) insertNode(ctx context.Context, ip string) error {
	e.logger.Sugar().Debugf("Try to insert node: %s", ip)
	var exists bool
	err := e.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM nodes WHERE id = $1)
	`, ip).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if node exists: %w", err)
	}

	if !exists {
		_, err := e.pool.Exec(ctx, `
			INSERT INTO nodes (id, mainstat)
			VALUES ($1, $2)
		`, ip, ip)
		if err != nil {
			return fmt.Errorf("failed to insert node: %w", err)
		}
	}

	return nil
}

func (e *postgresExporter) insertEdge(ctx context.Context, srcIp, destIp string) error {
	edgeId := srcIp + "-" + destIp

	e.logger.Sugar().Debugf("Try to insert edge: %s", edgeId)
	var exists bool
	err := e.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM edges WHERE id = $1)
	`, edgeId).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if edge exists: %w", err)
	}

	if !exists {
		_, err := e.pool.Exec(ctx, `
			INSERT INTO edges (id, source, target)
			VALUES ($1, $2, $3)
		`, edgeId, srcIp, destIp)
		if err != nil {
			return fmt.Errorf("failed to insert edge: %w", err)
		}
	}

	return nil
}

func (e *postgresExporter) Shutdown(ctx context.Context) error {
	e.pool.Close()
	return nil
}
