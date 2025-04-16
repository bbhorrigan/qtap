package accesslogs

import (
	"strconv"

	"github.com/qpoint-io/qtap/pkg/plugins"
	"github.com/qpoint-io/qtap/pkg/plugins/tools"
	"go.uber.org/zap"
)

// JSONPrinter implements the 	 interface for JSON format
type JSONPrinter struct {
	ctx        plugins.PluginContext
	reqheaders plugins.Headers
	resheaders plugins.Headers
	logger     *zap.Logger
	writer     *zap.Logger
}

// NewJSONPrinter creates a new JSONPrinter instance
func NewJSONPrinter(
	ctx plugins.PluginContext,
	reqheaders plugins.Headers,
	resheaders plugins.Headers,
	logger *zap.Logger,
	writer *zap.Logger,
) *JSONPrinter {
	return &JSONPrinter{
		ctx:        ctx,
		reqheaders: reqheaders,
		resheaders: resheaders,
		logger:     logger,
		writer:     writer,
	}
}

// PrintSummary implements Printer.PrintSummary
func (j *JSONPrinter) PrintSummary() {
	reqHeaders := tools.NewHeaderMap(j.reqheaders)
	qpointRequestID, _ := reqHeaders.QpointRequestID()
	url, _ := reqHeaders.URL()
	method, _ := reqHeaders.Method()
	bin := j.ctx.GetMetadata("process-bin").String()

	direction := "egress-external"
	if d := j.ctx.GetMetadata("direction"); d.OK() {
		direction = d.String()
	}

	resHeaders := tools.NewHeaderMap(j.resheaders)
	status, _ := resHeaders.Status()

	j.writer.Info("HTTP transaction",
		zap.String("bin", bin),
		zap.String("direction", direction),
		zap.String("method", method),
		zap.String("url", url),
		zap.Int("status", status),
		zap.String("qpoint_request_id", qpointRequestID))
}

// PrintDetails implements Printer.PrintDetails
func (j *JSONPrinter) PrintDetails() error {
	return j.printJSONDetails(false)
}

// PrintFull implements Printer.PrintFull
func (j *JSONPrinter) PrintFull() error {
	return j.printJSONDetails(true)
}

func (j *JSONPrinter) printJSONDetails(includeBody bool) error {
	reqHeaders := tools.NewHeaderMap(j.reqheaders)
	qpointRequestID, _ := reqHeaders.QpointRequestID()
	url, _ := reqHeaders.URL()
	method, _ := reqHeaders.Method()
	protocol := j.ctx.GetMetadata("protocol").String()

	direction := "egress-external"
	if d := j.ctx.GetMetadata("direction"); d.OK() {
		direction = d.String()
	}

	wrBytes := j.ctx.GetMetadata("wr_bytes").Int64()
	rdBytes := j.ctx.GetMetadata("rd_bytes").Int64()

	resHeaders := tools.NewHeaderMap(j.resheaders)
	status, _ := resHeaders.Status()

	req := map[string]any{
		"url":               url,
		"method":            method,
		"proto":             protocol,
		"qpoint_request_id": qpointRequestID,
		"headers":           j.reqheaders.All(),
	}
	if includeBody {
		if reqHeaders.BinaryContentType() {
			req["body"] = "\t(Omitted - Binary Format)"
		} else {
			req["body"] = string(j.ctx.GetRequestBodyBuffer().Copy())
		}
	}

	resp := map[string]any{
		"status":  status,
		"headers": j.resheaders.All(),
	}
	if includeBody {
		if resHeaders.BinaryContentType() {
			resp["body"] = "\t(Omitted - Binary Format)"
		} else {
			resp["body"] = string(j.ctx.GetResponseBodyBuffer().Copy())
		}
	}

	meta := map[string]string{
		"pid": j.ctx.GetMetadata("process-pid").String(),
		"exe": j.ctx.GetMetadata("process-exe").String(),
		// "container_id":   j.ctx.GetMetadata("process-container_id").String(),
		// "pod_id":         j.ctx.GetMetadata("process-pod_id").String(),
		"bytes_sent":     strconv.FormatInt(wrBytes, 10),
		"bytes_received": strconv.FormatInt(rdBytes, 10),
	}

	if cname := j.ctx.GetMetadata("process-container_name").String(); cname != "" && cname != "<nil>" {
		meta["container_name"] = cname
	}
	if cimage := j.ctx.GetMetadata("process-container_image").String(); cimage != "" && cimage != "<nil>" {
		meta["container_image"] = cimage
	}
	if pname := j.ctx.GetMetadata("process-pod_name").String(); pname != "" && pname != "<nil>" {
		meta["pod_name"] = pname
	}
	if pnamespace := j.ctx.GetMetadata("process-pod_namespace").String(); pnamespace != "" && pnamespace != "<nil>" {
		meta["pod_namespace"] = pnamespace
	}

	j.writer.Info("HTTP transaction",
		zap.Any("meta", meta),
		zap.Any("direction", direction),
		zap.Any("request", req),
		zap.Any("response", resp),
	)

	return nil
}
