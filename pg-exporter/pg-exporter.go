package pg_exporter

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4/pgxpool"
	"go.opentelemetry.io/collector/pdata/pcommon"
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
		if err := e.insertGraph(ctx, resourceSpan.Resource()); err != nil {
			return err
		}
	}
	return nil
}

func getStrFromRs(rs pcommon.Resource, key string) string {
	v, exist := rs.Attributes().Get(key)
	if !exist {
		return ""
	}
	return v.AsString()
}

func (e *postgresExporter) insertGraph(ctx context.Context, rs pcommon.Resource) error {
	srcIp := getStrFromRs(rs, "src.ip")
	destIp := getStrFromRs(rs, "dest.ip")
	_, _ = rs.Attributes().Get("dest.port")
	ns := getStrFromRs(rs, "k8s.namespace.name")
	deployName := getStrFromRs(rs, "k8s.deployment.name")
	nodeName := getStrFromRs(rs, "k8s.node.name")
	podName := getStrFromRs(rs, "k8s.pod.name")

	if err := e.upsertNode(ctx, srcIp, destIp, ns, deployName, nodeName, podName); err != nil {
		return fmt.Errorf("failed to upsert srcIp into nodes: %w", err)
	}

	if err := e.upsertEdge(ctx, srcIp, destIp); err != nil {
		return fmt.Errorf("failed to upsert edge into edges: %w", err)
	}

	return nil
}

func (e *postgresExporter) upsertNode(ctx context.Context, srcIp string, destIp string, ns string, deployName string, nodeName string, podName string) error {
	// upsert destination
	_, err := e.pool.Exec(ctx, `
			INSERT INTO nodes (id, mainstat)
			VALUES ($1, $2)
			ON CONFLICT (id) 
			DO UPDATE SET mainstat = $2
		`, destIp, destIp)
	if err != nil {
		return fmt.Errorf("failed to upsert node: %w", err)
	}

	// upsert source
	upsertNodeSql := `
			INSERT INTO nodes (id, mainstat, secondarystat, title, subtitle)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) 
			DO UPDATE SET 
			    mainstat = $2,
			    secondarystat = $3,
			    title = $4,
			    subtitle = $5
		`

	_, err = e.pool.Exec(ctx, upsertNodeSql, srcIp, srcIp, podName+"_"+deployName, nodeName, ns)
	if err != nil {
		return fmt.Errorf("failed to upsert node: %w", err)
	}

	return nil
}

func (e *postgresExporter) upsertEdge(ctx context.Context, srcIp, destIp string) error {
	upsertEdgeSql := `
			INSERT INTO edges (id, source, target, thickness)
			VALUES ($1, $2, $3, 1)
			ON CONFLICT (id) 
			DO UPDATE SET thickness = LN(edges.thickness + 1) + 1;
		`

	edgeId := srcIp + "-" + destIp
	_, err := e.pool.Exec(ctx, upsertEdgeSql, edgeId, srcIp, destIp)
	if err != nil {
		return fmt.Errorf("failed to insert edge: %w", err)
	}

	return nil
}

func (e *postgresExporter) Shutdown(ctx context.Context) error {
	e.pool.Close()
	return nil
}
