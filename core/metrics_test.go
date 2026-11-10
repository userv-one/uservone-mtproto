package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetricsClientCounters(t *testing.T) {
	metrics := NewMetrics()
	metrics.ClientConnected()
	metrics.ClientConnected()
	metrics.ClientDisconnected()
	metrics.ClientDisconnected()
	metrics.ClientDisconnected() // An unmatched disconnect must not underflow.

	current, total := metrics.ClientCounts()
	if current != 0 || total != 2 {
		t.Fatalf("ClientCounts() = (%d, %d), want (0, 2)", current, total)
	}
}

func TestMetricsPrometheusHandshakeErrors(t *testing.T) {
	metrics := NewMetrics()
	metrics.RecordHandshakeError("timeout")
	metrics.RecordHandshakeError("timeout")
	metrics.RecordHandshakeError("invalid")

	response := httptest.NewRecorder()
	metrics.PrometheusHandler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))

	if contentType := response.Header().Get("Content-Type"); contentType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	body := response.Body.String()
	for _, want := range []string{
		"# TYPE uservone_mtproto_handshake_errors_total counter\n",
		`uservone_mtproto_handshake_errors_total{category="invalid"} 1` + "\n",
		`uservone_mtproto_handshake_errors_total{category="timeout"} 2` + "\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Prometheus response missing %q:\n%s", want, body)
		}
	}
}

func TestMetricsDCStatus(t *testing.T) {
	metrics := NewMetrics()
	now := time.Unix(1700000000, 0)
	metrics.now = func() time.Time { return now }

	metrics.RecordDCSuccess(2)
	now = time.Unix(1700000010, 0)
	metrics.RecordDCFailure(2)
	metrics.RecordDCSuccess(3)

	status, ok := metrics.DCStatus(2)
	if !ok {
		t.Fatal("DCStatus(2) reported an unknown DC")
	}
	if status.Reachable || status.Successes != 1 || status.Failures != 1 || status.LastSuccessUnix != 1700000000 {
		t.Fatalf("DCStatus(2) = %+v, want unreachable with one success, one failure, and retained timestamp", status)
	}
	status, ok = metrics.DCStatus(3)
	if !ok || !status.Reachable || status.Successes != 1 || status.Failures != 0 || status.LastSuccessUnix != 1700000010 {
		t.Fatalf("DCStatus(3) = (%+v, %t), want current success at new timestamp", status, ok)
	}
	if _, ok := metrics.DCStatus(4); ok {
		t.Fatal("DCStatus(4) reported an unobserved DC")
	}
}

func TestMetricsPrometheusClientAndDCMetrics(t *testing.T) {
	metrics := NewMetrics()
	metrics.now = func() time.Time { return time.Unix(1700000000, 0) }
	metrics.ClientConnected()
	metrics.ClientConnected()
	metrics.ClientDisconnected()
	metrics.RecordDCSuccess(2)
	metrics.RecordDCFailure(1)

	response := httptest.NewRecorder()
	metrics.PrometheusHandler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	for _, want := range []string{
		"# TYPE uservone_mtproto_client_connections_current gauge\n",
		"uservone_mtproto_client_connections_current 1\n",
		"# TYPE uservone_mtproto_client_connections_total counter\n",
		"uservone_mtproto_client_connections_total 2\n",
		"# TYPE uservone_mtproto_upstream_dc_reachable gauge\n",
		`uservone_mtproto_upstream_dc_reachable{dc="1"} 0` + "\n",
		`uservone_mtproto_upstream_dc_reachable{dc="2"} 1` + "\n",
		`uservone_mtproto_upstream_dc_success_total{dc="1"} 0` + "\n",
		`uservone_mtproto_upstream_dc_success_total{dc="2"} 1` + "\n",
		`uservone_mtproto_upstream_dc_failure_total{dc="1"} 1` + "\n",
		`uservone_mtproto_upstream_dc_failure_total{dc="2"} 0` + "\n",
		`uservone_mtproto_upstream_dc_last_success_timestamp_seconds{dc="1"} 0` + "\n",
		`uservone_mtproto_upstream_dc_last_success_timestamp_seconds{dc="2"} 1700000000` + "\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Prometheus response missing %q:\n%s", want, body)
		}
	}
}

func TestMetricsHealthUnknownBeforeDCObservation(t *testing.T) {
	metrics := NewMetrics()
	response := httptest.NewRecorder()
	metrics.HealthHandler().ServeHTTP(response, httptest.NewRequest("GET", "/health", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unobserved health response code = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	var health struct {
		Status      string              `json:"status"`
		Datacenters map[string]DCStatus `json:"datacenters"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode unobserved health response: %v", err)
	}
	if health.Status != "unknown" {
		t.Fatalf("unobserved health status = %q, want unknown", health.Status)
	}
	if len(health.Datacenters) != 0 {
		t.Fatalf("unobserved health datacenters = %v, want empty", health.Datacenters)
	}
}

func TestMetricsHealthJSON(t *testing.T) {
	metrics := NewMetrics()
	metrics.now = func() time.Time { return time.Unix(1700000000, 0) }
	metrics.ClientConnected()
	metrics.RecordHandshakeError("timeout")
	metrics.RecordHandshakeError("timeout")
	metrics.RecordDCSuccess(2)

	type health struct {
		Status  string `json:"status"`
		Clients struct {
			Current int64  `json:"current"`
			Total   uint64 `json:"total"`
		} `json:"clients"`
		HandshakeErrors map[string]uint64   `json:"handshake_errors"`
		Datacenters     map[string]DCStatus `json:"datacenters"`
	}
	response := httptest.NewRecorder()
	metrics.HealthHandler().ServeHTTP(response, httptest.NewRequest("GET", "/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("healthy response code = %d, want %d", response.Code, http.StatusOK)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
	var healthy health
	if err := json.Unmarshal(response.Body.Bytes(), &healthy); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if healthy.Status != "ok" || healthy.Clients.Current != 1 || healthy.Clients.Total != 1 {
		t.Fatalf("health response = %+v, want ok with one client", healthy)
	}
	if healthy.HandshakeErrors["timeout"] != 2 {
		t.Fatalf("handshake errors = %v, want timeout count 2", healthy.HandshakeErrors)
	}
	if status := healthy.Datacenters["2"]; !status.Reachable || status.Successes != 1 || status.LastSuccessUnix != 1700000000 {
		t.Fatalf("DC health = %+v, want successful DC 2", status)
	}

	metrics.RecordDCFailure(2)
	response = httptest.NewRecorder()
	metrics.HealthHandler().ServeHTTP(response, httptest.NewRequest("GET", "/health", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("degraded response code = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	var degraded health
	if err := json.Unmarshal(response.Body.Bytes(), &degraded); err != nil {
		t.Fatalf("decode degraded response: %v", err)
	}
	if degraded.Status != "degraded" || degraded.Datacenters["2"].Reachable || degraded.Datacenters["2"].LastSuccessUnix != 1700000000 {
		t.Fatalf("degraded health = %+v, want unreachable DC with retained success timestamp", degraded)
	}
}

func TestMetricsConcurrentAccess(t *testing.T) {
	var metrics Metrics // The zero value must be usable by embedding code.
	metrics.now = func() time.Time { return time.Unix(1700000000, 0) }
	const (
		workers    = 8
		iterations = 100
	)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				metrics.ClientConnected()
				metrics.RecordHandshakeError("timeout")
				if (worker+iteration)%2 == 0 {
					metrics.RecordDCSuccess(1)
				} else {
					metrics.RecordDCFailure(1)
				}
				if iteration%25 == 0 {
					metrics.PrometheusHandler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/metrics", nil))
					metrics.HealthHandler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/health", nil))
				}
				metrics.ClientDisconnected()
			}
		}(worker)
	}
	wait.Wait()

	current, total := metrics.ClientCounts()
	if current != 0 || total != workers*iterations {
		t.Fatalf("ClientCounts() = (%d, %d), want (0, %d)", current, total, workers*iterations)
	}
	status, ok := metrics.DCStatus(1)
	if !ok || status.Successes+status.Failures != workers*iterations || status.LastSuccessUnix != 1700000000 {
		t.Fatalf("DCStatus(1) = (%+v, %t), want %d observations", status, ok, workers*iterations)
	}
	response := httptest.NewRecorder()
	metrics.PrometheusHandler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if want := `uservone_mtproto_handshake_errors_total{category="timeout"} 800` + "\n"; !strings.Contains(response.Body.String(), want) {
		t.Fatalf("Prometheus response missing %q:\n%s", want, response.Body.String())
	}
}
