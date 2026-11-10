package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metrics tracks proxy activity without retaining client or handshake data.
type Metrics struct {
	mu              sync.RWMutex
	currentClients  int64
	totalClients    uint64
	handshakeErrors map[string]uint64
	datacenters     map[int]DCStatus
	now             func() time.Time
}

// DCStatus is a snapshot of reachability observations for one upstream DC.
type DCStatus struct {
	Reachable       bool   `json:"reachable"`
	Successes       uint64 `json:"successes"`
	Failures        uint64 `json:"failures"`
	LastSuccessUnix int64  `json:"last_success_unix"`
}

// NewMetrics returns an empty metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{now: time.Now}
}

// ClientConnected records one accepted client connection.
func (m *Metrics) ClientConnected() {
	m.mu.Lock()
	m.currentClients++
	m.totalClients++
	m.mu.Unlock()
}

// ClientDisconnected records one closed client connection.
func (m *Metrics) ClientDisconnected() {
	m.mu.Lock()
	if m.currentClients > 0 {
		m.currentClients--
	}
	m.mu.Unlock()
}

// ClientCounts returns a consistent snapshot of current and total clients.
func (m *Metrics) ClientCounts() (current int64, total uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentClients, m.totalClients
}

// RecordHandshakeError increments the counter for a caller-supplied category.
// Callers should use stable category names, not error text or handshake data.
func (m *Metrics) RecordHandshakeError(category string) {
	m.mu.Lock()
	if m.handshakeErrors == nil {
		m.handshakeErrors = make(map[string]uint64)
	}
	m.handshakeErrors[category]++
	m.mu.Unlock()
}

// RecordDCSuccess records a successful upstream connection and its timestamp.
func (m *Metrics) RecordDCSuccess(dc int) {
	m.recordDC(dc, true)
}

// RecordDCFailure records a failed upstream connection.
func (m *Metrics) RecordDCFailure(dc int) {
	m.recordDC(dc, false)
}

func (m *Metrics) recordDC(dc int, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.datacenters == nil {
		m.datacenters = make(map[int]DCStatus)
	}
	status := m.datacenters[dc]
	status.Reachable = success
	if success {
		status.Successes++
		now := m.now
		if now == nil {
			now = time.Now
		}
		status.LastSuccessUnix = now().Unix()
	} else {
		status.Failures++
	}
	m.datacenters[dc] = status
}

// DCStatus returns the latest status for dc and whether it has been observed.
func (m *Metrics) DCStatus(dc int) (DCStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status, ok := m.datacenters[dc]
	return status, ok
}

type metricsSnapshot struct {
	currentClients  int64
	totalClients    uint64
	handshakeErrors map[string]uint64
	datacenters     map[int]DCStatus
}

func (m *Metrics) snapshot() metricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := metricsSnapshot{
		currentClients:  m.currentClients,
		totalClients:    m.totalClients,
		handshakeErrors: make(map[string]uint64, len(m.handshakeErrors)),
		datacenters:     make(map[int]DCStatus, len(m.datacenters)),
	}
	for category, count := range m.handshakeErrors {
		snapshot.handshakeErrors[category] = count
	}
	for dc, status := range m.datacenters {
		snapshot.datacenters[dc] = status
	}
	return snapshot
}

// PrometheusHandler returns an HTTP handler for the metrics text exposition.
func (m *Metrics) PrometheusHandler() http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		snapshot := m.snapshot()
		categories := make([]string, 0, len(snapshot.handshakeErrors))
		for category := range snapshot.handshakeErrors {
			categories = append(categories, category)
		}
		sort.Strings(categories)
		datacenters := make([]int, 0, len(snapshot.datacenters))
		for dc := range snapshot.datacenters {
			datacenters = append(datacenters, dc)
		}
		sort.Ints(datacenters)

		var body strings.Builder
		body.WriteString("# TYPE uservone_mtproto_client_connections_current gauge\n")
		fmt.Fprintf(&body, "uservone_mtproto_client_connections_current %d\n", snapshot.currentClients)
		body.WriteString("# TYPE uservone_mtproto_client_connections_total counter\n")
		fmt.Fprintf(&body, "uservone_mtproto_client_connections_total %d\n", snapshot.totalClients)
		body.WriteString("# TYPE uservone_mtproto_handshake_errors_total counter\n")
		for _, category := range categories {
			fmt.Fprintf(&body, "uservone_mtproto_handshake_errors_total{category=%q} %d\n", category, snapshot.handshakeErrors[category])
		}
		body.WriteString("# TYPE uservone_mtproto_upstream_dc_reachable gauge\n")
		for _, dc := range datacenters {
			reachable := 0
			if snapshot.datacenters[dc].Reachable {
				reachable = 1
			}
			fmt.Fprintf(&body, "uservone_mtproto_upstream_dc_reachable{dc=\"%d\"} %d\n", dc, reachable)
		}
		body.WriteString("# TYPE uservone_mtproto_upstream_dc_success_total counter\n")
		for _, dc := range datacenters {
			fmt.Fprintf(&body, "uservone_mtproto_upstream_dc_success_total{dc=\"%d\"} %d\n", dc, snapshot.datacenters[dc].Successes)
		}
		body.WriteString("# TYPE uservone_mtproto_upstream_dc_failure_total counter\n")
		for _, dc := range datacenters {
			fmt.Fprintf(&body, "uservone_mtproto_upstream_dc_failure_total{dc=\"%d\"} %d\n", dc, snapshot.datacenters[dc].Failures)
		}
		body.WriteString("# TYPE uservone_mtproto_upstream_dc_last_success_timestamp_seconds gauge\n")
		for _, dc := range datacenters {
			fmt.Fprintf(&body, "uservone_mtproto_upstream_dc_last_success_timestamp_seconds{dc=\"%d\"} %d\n", dc, snapshot.datacenters[dc].LastSuccessUnix)
		}
		response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = response.Write([]byte(body.String()))
	})
}

type healthResponse struct {
	Status          string              `json:"status"`
	Clients         healthClients       `json:"clients"`
	HandshakeErrors map[string]uint64   `json:"handshake_errors"`
	Datacenters     map[string]DCStatus `json:"datacenters"`
}

type healthClients struct {
	Current int64  `json:"current"`
	Total   uint64 `json:"total"`
}

// HealthHandler returns an HTTP handler with a JSON health snapshot.
// Health is unknown and unavailable until at least one DC has been observed.
// A DC whose latest attempt failed makes the response degraded with status 503.
func (m *Metrics) HealthHandler() http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		snapshot := m.snapshot()
		health := healthResponse{
			Status: "unknown",
			Clients: healthClients{
				Current: snapshot.currentClients,
				Total:   snapshot.totalClients,
			},
			HandshakeErrors: snapshot.handshakeErrors,
			Datacenters:     make(map[string]DCStatus, len(snapshot.datacenters)),
		}
		statusCode := http.StatusServiceUnavailable
		if len(snapshot.datacenters) > 0 {
			health.Status = "ok"
			statusCode = http.StatusOK
		}
		for dc, status := range snapshot.datacenters {
			health.Datacenters[strconv.Itoa(dc)] = status
			if !status.Reachable {
				health.Status = "degraded"
				statusCode = http.StatusServiceUnavailable
			}
		}
		body, err := json.Marshal(health)
		if err != nil {
			http.Error(response, "health encoding failed", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(statusCode)
		_, _ = response.Write(body)
	})
}
