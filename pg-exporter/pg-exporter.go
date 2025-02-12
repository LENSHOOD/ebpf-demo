package pg_exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v4/pgxpool"
	ebpfreceiver "github.com/open-telemetry/otelcol-ebpf-demo/epbf-receiver"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
	"os"
	"strconv"
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

	if cfg.DbInitSqlPath != "" {
		initSql, err := os.ReadFile(cfg.DbInitSqlPath)
		if err != nil {
			logger.Sugar().Fatalf("Failed to init db: %v", err)
		}

		if _, err = pool.Exec(context.Background(), string(initSql)); err != nil {
			logger.Sugar().Fatalf("Failed to init db: %v", err)
		}
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
		case ebpfreceiver.NodeSrc:
			fallthrough
		case ebpfreceiver.NodeDest:
			ip := getStrFromRs(rs, ebpfreceiver.MetadataIp)
			ns := getStrFromRs(rs, ebpfreceiver.MetadataNS)
			deployName := getStrFromRs(rs, ebpfreceiver.MetadataDeployName)
			nodeName := getStrFromRs(rs, ebpfreceiver.MetadataNodeName)
			podName := getStrFromRs(rs, ebpfreceiver.MetadataPodName)

			e.logger.Sugar().Debugf("Insert Node: %s", ip)
			if err := e.upsertNode(ctx, ip, ns, deployName, nodeName, podName); err != nil {
				return fmt.Errorf("failed to upsert into nodes: %w", err)
			}
		case ebpfreceiver.Body:
			srcIp := getStrFromRs(rs, ebpfreceiver.MetadataSrc)
			destIp := getStrFromRs(rs, ebpfreceiver.MetadataDest)
			e.logger.Sugar().Debugf("Insert Edge: %s - %s", srcIp, destIp)
			if err := e.upsertEdge(ctx, srcIp, destIp); err != nil {
				return fmt.Errorf("failed to upsert edge into edges: %w", err)
			}

			srcPort := getIntFromRs(rs, ebpfreceiver.MetadataSrcPort)
			destPort := getIntFromRs(rs, ebpfreceiver.MetadataDestPort)

			e.logger.Sugar().Debugf("Insert Net Traces: %s:%d - %s:%d", srcIp, srcPort, destIp, destPort)
			if err := e.upsertBody(ctx, rs, srcIp, srcPort, destIp, destPort); err != nil {
				return fmt.Errorf("failed to upsert body into net_traces: %w", err)
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

func (e *postgresExporter) upsertBody(ctx context.Context, rs pcommon.Resource, srcIp string, srcPort int64, destIp string, destPort int64) error {
	trafficType := ebpfreceiver.TT(getIntFromRs(rs, ebpfreceiver.TrafficType))
	id := getIntFromRs(rs, ebpfreceiver.MetadataTrafficIdentifier)

	var existingPayload []byte
	query := `SELECT payload FROM net_traces WHERE id = $1`
	if err := e.pool.QueryRow(ctx, query, id).Scan(&existingPayload); err != nil {
		payload, err := e.buildPayload(trafficType, rs, []byte{})
		if err != nil {
			e.logger.Sugar().Errorf("Failed to build payload: %v", err)
		}

		protocol := "UNKNOWN"
		switch trafficType {
		case ebpfreceiver.TCP:
			protocol = "TCP"
		case ebpfreceiver.UDP:
			protocol = "UDP"
		case ebpfreceiver.HTTP_REQ:
			fallthrough
		case ebpfreceiver.HTTP_RESP:
			protocol = "HTTP"
		case ebpfreceiver.DNS_REQ:
			fallthrough
		case ebpfreceiver.DNS_RESP:
			protocol = "DNS"
		}

		insertSQL := `INSERT INTO net_traces (id, src_ip, src_port, dest_ip, dest_port, protocol, payload) 
					  VALUES ($1, $2, $3, $4, $5, $6, $7)`
		if _, err := e.pool.Exec(ctx, insertSQL, id, srcIp, srcPort, destIp, destPort, protocol, payload); err != nil {
			return fmt.Errorf("failed to insert into net_traces: %w", err)
		}

		return nil
	}

	payload, err := e.buildPayload(trafficType, rs, existingPayload)
	if err != nil {
		e.logger.Sugar().Errorf("Failed to build payload: %v", err)
	}

	updateSQL := `UPDATE net_traces SET payload = $1 WHERE id = $2`
	if _, err := e.pool.Exec(ctx, updateSQL, payload, id); err != nil {
		return fmt.Errorf("failed to update net_traces: %w", err)
	}

	return nil
}

type HttpStruct struct {
	Method      string `json:"method"`
	Uri         string `json:"uri"`
	Version     string `json:"version"`
	Status      string `json:"status"`
	ReqContent  string `json:"req_content"`
	RespContent string `json:"resp_content"`
	Start       string `json:"start"`
	End         string `json:"end"`
}

type DnsStruct struct {
	ReqContent  string `json:"req_content"`
	RespContent string `json:"resp_content"`
	Start       string `json:"start"`
	End         string `json:"end"`
}

func (e *postgresExporter) buildPayload(tt ebpfreceiver.TT, rs pcommon.Resource, existingPayload []byte) ([]byte, error) {
	switch tt {
	case ebpfreceiver.HTTP_REQ:
		http := HttpStruct{}
		if len(existingPayload) != 0 {
			if err := json.Unmarshal(existingPayload, &http); err != nil {
				return []byte{}, fmt.Errorf("unmarshal error: %v", err)
			}
		}
		http.Start = strconv.FormatInt(getIntFromRs(rs, ebpfreceiver.Timestamp), 10)
		http.Uri = getStrFromRs(rs, ebpfreceiver.HttpUri)
		http.Method = getStrFromRs(rs, ebpfreceiver.HttpMethod)
		http.Version = getStrFromRs(rs, ebpfreceiver.HttpVersion)
		http.ReqContent = getStrFromRs(rs, ebpfreceiver.BodyContent)
		return json.Marshal(http)

	case ebpfreceiver.HTTP_RESP:
		http := HttpStruct{}
		if len(existingPayload) != 0 {
			if err := json.Unmarshal(existingPayload, &http); err != nil {
				return []byte{}, fmt.Errorf("unmarshal error: %v", err)
			}
		}
		http.End = strconv.FormatInt(getIntFromRs(rs, ebpfreceiver.Timestamp), 10)
		http.Status = getStrFromRs(rs, ebpfreceiver.HttpStatus)
		http.RespContent = getStrFromRs(rs, ebpfreceiver.BodyContent)
		return json.Marshal(http)

	case ebpfreceiver.DNS_REQ:
		dns := DnsStruct{}
		if len(existingPayload) != 0 {
			if err := json.Unmarshal(existingPayload, &dns); err != nil {
				return []byte{}, fmt.Errorf("unmarshal error: %v", err)
			}
		}
		dns.Start = strconv.FormatInt(getIntFromRs(rs, ebpfreceiver.Timestamp), 10)
		dns.ReqContent = getStrFromRs(rs, ebpfreceiver.BodyContent)
		return json.Marshal(dns)
	case ebpfreceiver.DNS_RESP:
		dns := DnsStruct{}
		if len(existingPayload) != 0 {
			if err := json.Unmarshal(existingPayload, &dns); err != nil {
				return []byte{}, fmt.Errorf("unmarshal error: %v", err)
			}
		}
		dns.End = strconv.FormatInt(getIntFromRs(rs, ebpfreceiver.Timestamp), 10)
		dns.RespContent = getStrFromRs(rs, ebpfreceiver.BodyContent)
		return json.Marshal(dns)
	default:
		return json.Marshal("")
	}
}

func (e *postgresExporter) Shutdown(ctx context.Context) error {
	e.pool.Close()
	return nil
}
