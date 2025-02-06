package pg_exporter

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4/pgxpool"
	ebpfreceiver "github.com/open-telemetry/otelcol-ebpf-demo/epbf-receiver"
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
	if err := e.insertGraph(ctx, resourceSpans); err != nil {
		return err
	}
	return nil
}

func getIntFromRs(rs pcommon.Resource, key string) int64 {
	v, exist := rs.Attributes().Get(key)
	if !exist {
		return 0
	}
	return v.Int()
}

func getStrFromRs(rs pcommon.Resource, key string) string {
	v, exist := rs.Attributes().Get(key)
	if !exist {
		return ""
	}
	return v.AsString()
}

func (e *postgresExporter) insertGraph(ctx context.Context, rss ptrace.ResourceSpansSlice) error {
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i).Resource()
		kind := ebpfreceiver.Kind(getIntFromRs(rs, ebpfreceiver.DirectionKey))
		switch kind {
		case ebpfreceiver.NODE_SRC:
			fallthrough
		case ebpfreceiver.NODE_DEST:
			ip := getStrFromRs(rs, ebpfreceiver.MetadataIp)
			ns := getStrFromRs(rs, ebpfreceiver.MetadataNS)
			deployName := getStrFromRs(rs, ebpfreceiver.MetadataDeployName)
			nodeName := getStrFromRs(rs, ebpfreceiver.MetadataNodeName)
			podName := getStrFromRs(rs, ebpfreceiver.MetadataPodName)

			e.logger.Sugar().Debugf("Insert Node: %s", ip)
			if err := e.upsertNode(ctx, ip, ns, deployName, nodeName, podName); err != nil {
				return fmt.Errorf("failed to upsert into nodes: %w", err)
			}
		case ebpfreceiver.EDGE:
			srcIp := getStrFromRs(rs, ebpfreceiver.MetadataSrc)
			destIp := getStrFromRs(rs, ebpfreceiver.MetadataDest)
			e.logger.Sugar().Debugf("Insert Edge: %s - %s", srcIp, destIp)
			if err := e.upsertEdge(ctx, srcIp, destIp); err != nil {
				return fmt.Errorf("failed to upsert edge into edges: %w", err)
			}
		}
	}

	return nil
}

func (e *postgresExporter) upsertNode(ctx context.Context, ip string, ns string, deployName string, nodeName string, podName string) error {
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

	_, err := e.pool.Exec(ctx, upsertNodeSql, ip, ip, deployName+"."+ns, podName, nodeName)
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
		return fmt.Errorf("failed to upsert edge: %w", err)
	}

	return nil
}

func (e *postgresExporter) Shutdown(ctx context.Context) error {
	e.pool.Close()
	return nil
}
