package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Handler() http.Handler {
	return promhttp.Handler()
}
