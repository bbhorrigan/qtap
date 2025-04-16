package connection

import (
	"strconv"
	"strings"
	"time"

	"github.com/qpoint-io/qtap/pkg/qnet"
	"github.com/qpoint-io/qtap/pkg/telemetry"
	"go.uber.org/zap"
)

func (m *Manager) generateAuditLog(conn *Connection) {
	if conn.HandlerType == HandlerType_FORWARDING {
		conn.logger.Debug("generateAuditLog: forwarding connection detected, ignoring audit")
		return
	}

	// if this is DNS, ensure we're wanted
	if m.config != nil && conn.Protocol == Protocol_DNS && !m.config.Tap.AuditIncludeDNS {
		m.logger.Debug("generateAuditLog: DNS audit log disabled",
			zap.String("conn_pid_id", conn.connPIDKey.String()),
			zap.String("local_addr", conn.OpenEvent.Local.String()),
			zap.String("remote_addr", conn.OpenEvent.Remote.String()))
		return
	}

	// identify directional aspects
	var direction string
	var srcAddr qnet.NetAddr
	var dstAddr qnet.NetAddr

	// set original destination if available
	if od := conn.OriginalDestination; od != nil {
		conn.OpenEvent.Remote = *od
	}

	// client vs server
	switch conn.OpenEvent.Source {
	case Client:
		if conn.OpenEvent.Remote.IP.IsPrivate() {
			direction = "egress-internal"
		} else {
			direction = "egress-external"
		}
		srcAddr = conn.OpenEvent.Local
		dstAddr = conn.OpenEvent.Remote
	case Server:
		direction = "ingress"
		srcAddr = conn.OpenEvent.Remote
		dstAddr = conn.OpenEvent.Local
	}

	// get the domain
	domain := conn.Domain()

	// if the domain is '<nil>' it means the destination IP had a 0 length and something was
	// interupted in the socket layer. The connection is invalid and we can safely ignore it.
	if strings.EqualFold(domain, "<nil>") {
		m.logger.Debug("generateAuditLog: domain is <nil>, ignoring",
			zap.String("conn_pid_id", conn.connPIDKey.String()),
			zap.String("local_addr", conn.OpenEvent.Local.String()),
			zap.String("remote_addr", conn.OpenEvent.Remote.String()))
		return
	}

	// audit logs are disabled, nothing to do
	if m.config != nil {
		if !m.config.Services.HasAnyEventStores() {
			m.logger.Debug("generateAuditLog: audit logs disabled",
				zap.String("conn_pid_id", conn.connPIDKey.String()),
				zap.String("local_addr", conn.OpenEvent.Local.String()),
				zap.String("remote_addr", conn.OpenEvent.Remote.String()))
			return
		}
	}

	// determine the column name
	columnName := func(name string) string {
		if m.config != nil {
			switch name {
			case "endpoint":
				return "endpointId"
			case "exe":
				return "sourceExe"
			case "exeFilename":
				return "sourceExeFilename"
			case "containerId":
				return "sourceContainerId"
			case "podId":
				return "sourcePodId"
			case "hostname":
				return "sourceHostname"
			case "systemUser":
				return "sourceSystemUser"
			default:
				return name
			}
		}

		return name
	}

	// assemble the audit log fields
	fields := []zap.Field{
		zap.Bool("finalized", conn.CloseEvent != nil),
		zap.Uint32("part", conn.auditCount),
		zap.String("connectionId", conn.ID()),
		zap.String(columnName("timestamp"), time.Now().UTC().Format(time.RFC3339)),
		zap.String(columnName("endpoint"), domain),
		zap.String(columnName("direction"), direction),
		zap.String(columnName("qpointAgent"), "tap"),
		zap.String(columnName("destinationAddress"), dstAddr.IP.String()),
		zap.String(columnName("destinationPort"), strconv.FormatUint(uint64(dstAddr.Port), 10)),
		zap.String(columnName("destinationProtocol"), conn.OpenEvent.SocketType.String()),
	}

	// telemetry
	fields = append(fields, zap.String("instanceId", telemetry.InstanceID()))
	fields = append(fields, zap.String("qpointHostname", telemetry.Hostname()))

	if conn.CloseEvent != nil {
		fields = append(fields, zap.Int64(columnName("bytesReceived"), conn.CloseEvent.RdBytes))
		fields = append(fields, zap.Int64(columnName("bytesSent"), conn.CloseEvent.WrBytes))
	}

	if conn.TLSClientHello != nil {
		fields = append(fields, zap.String(columnName("tlsVersion"), conn.TLSClientHello.Version.String()))
	}

	// add src net if we know it
	if srcAddr.Port > 0 {
		// get the source IP
		srcIp := srcAddr.IP.String()

		fields = append(fields, zap.String(columnName("sourceProtocol"), conn.OpenEvent.SocketType.String()))
		fields = append(fields, zap.String(columnName("sourceAddress"), srcIp))
		fields = append(fields, zap.String(columnName("sourcePort"), strconv.FormatUint(uint64(srcAddr.Port), 10)))
	} else {
		m.logger.Debug("ignoring invalid source address, source port is 0", zap.Any("srcAddr", srcAddr))
	}

	// find the associated process for extra metadata
	if proc := conn.process; proc != nil {
		// add the process executable
		fields = append(fields, zap.String(columnName("exe"), proc.Exe))

		fields = append(fields, zap.String(columnName("exeFilename"), proc.ExeFilename))

		// // add containerID if exists
		// if proc.ContainerID != "root" {
		// 	fields = append(fields, zap.String(columnName("containerId"), proc.ContainerID))
		// }

		// // add podID if exists
		// if proc.PodID != "" {
		// 	fields = append(fields, zap.String(columnName("podId"), proc.PodID))
		// }

		// hostname
		if hostname, _ := proc.Hostname(); hostname != "" {
			// add field
			fields = append(fields, zap.String(columnName("hostname"), hostname))
		}

		// system user
		if user, _ := proc.User(); user != "" {
			fields = append(fields, zap.String(columnName("systemUser"), user))
		}

		// container
		if c := proc.Container; c != nil {
			fields = append(fields, c.Fields()...)
		}
	}

	// add tags
	fields = append(fields, zap.Strings(columnName("tags"), conn.tags.List()))

	// generate the log
	m.auditLogger.Log(fields...)

	// debug log
	conn.logger.Debug("audit log", zap.Any("fields", fields))

	// increment report count for next report
	conn.auditCount++
}
