package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bog/internal/client"
	"bog/internal/store"
)

const aggregateProbeCursor = "Bog-Next-Cursor"

var aggregateProbeStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

type aggregateProbeSource struct {
	next atomic.Uint64
	hold func(context.Context, PageRequest) error
}

func (s *aggregateProbeSource) Page(ctx context.Context, req PageRequest, work *store.QueryWork) (PageResult, error) {
	if s.hold != nil {
		if err := s.hold(ctx, req); err != nil {
			return PageResult{}, err
		}
	}
	if err := work.Charge(2); err != nil {
		return PageResult{}, err
	}
	result := PageResult{Capture: req.Capture}
	if req.Snapshot && result.Capture == "" {
		result.Capture = strconv.FormatUint(s.next.Add(1), 10)
	}
	lines := []string{"opening", strings.Repeat("x", 2500), "terminal"}
	for i, line := range lines {
		pos := PagePosition(strconv.Itoa(i + 1))
		if pos <= req.After {
			continue
		}
		if len(result.Rows) == req.Limit {
			result.More = req.Snapshot
			break
		}
		result.Rows = append(result.Rows, PageRow{
			Row:      store.Row{TS: aggregateProbeStart.Add(time.Duration(i) * time.Second), Line: line},
			Position: pos,
		})
	}
	return result, nil
}

func (*aggregateProbeSource) Release(string) error { return nil }

type aggregateProbeWriter struct {
	*httptest.ResponseRecorder
	hold func()
}

func (w aggregateProbeWriter) Write([]byte) (int, error) {
	w.hold()
	return 0, io.ErrClosedPipe
}

func aggregateProbeTarget(cursor string) string {
	query := url.Values{
		"start":    {aggregateProbeStart.Format(time.RFC3339Nano)},
		"end":      {aggregateProbeStart.Add(time.Hour).Format(time.RFC3339Nano)},
		"contains": {""},
		"limit":    {"1"},
	}
	if cursor == "" {
		query.Set("page", "1")
	} else {
		query.Set("cursor", cursor)
	}
	return "/query?" + query.Encode()
}

func aggregateProbePage(t *testing.T, handler http.Handler, cursor, line string, more bool) (string, string) {
	t.Helper()
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, httptest.NewRequest(http.MethodGet, aggregateProbeTarget(cursor), nil))
	body := out.Body.String()
	next := out.Header().Values(aggregateProbeCursor)
	var row store.Row
	if out.Code != 200 || out.Header().Get("Content-Type") != "application/x-ndjson" ||
		out.Header().Get("Content-Length") != strconv.Itoa(len(body)) ||
		!strings.HasSuffix(body, "\n") || strings.Count(body, "\n") != 1 ||
		json.Unmarshal([]byte(body), &row) != nil || row.Line != line {
		t.Fatalf("page status=%d headers=%v body length=%d, expected line %q", out.Code, out.Header(), len(body), line[:min(20, len(line))])
	}
	if !more && len(next) == 0 {
		return body, ""
	}
	if !more || len(next) != 1 || next[0] == "" || next[0] == cursor {
		t.Fatalf("unexpected cursor headers %v (more=%t)", next, more)
	}
	return body, next[0]
}

func aggregateProbeRefusal(t *testing.T, baseURL, cursor, resource string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+aggregateProbeTarget(cursor), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
	closeErr := response.Body.Close()
	contentType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	message, newline := strings.CutSuffix(string(body), "\n")
	if response.StatusCode != 503 || readErr != nil || closeErr != nil || mediaErr != nil ||
		contentType != "text/plain" || len(response.Header.Values("Content-Type")) != 1 ||
		len(response.Header.Values(aggregateProbeCursor)) != 0 ||
		(response.ContentLength >= 0 && response.ContentLength != int64(len(body))) ||
		!newline || len(body) > 1024 || strings.ContainsAny(message, "\r\n{}") {
		t.Fatalf("%s: incomplete or invalid refusal: HTTP %d, headers=%v, body=%q, read=%v, close=%v",
			resource, response.StatusCode, response.Header, body[:min(160, len(body))], readErr, closeErr)
	}
	switch resource {
	case "query capacity exhausted", "query work budget exhausted":
		if message != resource {
			t.Fatalf("expected %q, got %q", resource, message)
		}
	default:
		diagnostic := strings.ReplaceAll(strings.ToLower(message), "-", " ")
		diagnostic = strings.ReplaceAll(diagnostic, "prepared response bytes", "prepared bytes")
		diagnostic = strings.ReplaceAll(diagnostic, "pinned captures", "capture count")
		diagnostic = strings.ReplaceAll(diagnostic, "live captures", "capture count")
		if !strings.Contains(diagnostic, resource) {
			t.Fatalf("expected %s exhaustion diagnostic, got %q", resource, message)
		}
	}
	c, err := client.New(baseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	page, err := c.FetchPage(ctx, client.Query{Start: aggregateProbeStart, End: aggregateProbeStart.Add(time.Hour), Limit: 1}, cursor)
	var status *client.HTTPError
	if !errors.As(err, &status) || status.StatusCode != 503 || status.Body != string(body) ||
		status.Cause != nil || !status.Retryable() || status.CursorRejected || errors.Is(err, client.ErrCaptureExpired) ||
		len(page.Rows) != 0 || page.NextCursor != "" {
		t.Fatalf("%s: client did not return the complete retryable refusal: page=%+v error=%v", resource, page, err)
	}
}

func TestSlipwayQueryAggregateAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits QueryAdmissionLimits
		slots  int
		work   uint64
	}{
		{"prepared bytes", QueryAdmissionLimits{PreparedBytes: 4096, ScanBuffers: 8, Captures: 8}, 4, DefaultQueryWorkBudget},
		{"scan buffers", QueryAdmissionLimits{PreparedBytes: 32768, ScanBuffers: 1, Captures: 8}, 4, DefaultQueryWorkBudget},
		{"capture count", QueryAdmissionLimits{PreparedBytes: 32768, ScanBuffers: 8, Captures: 2}, 4, DefaultQueryWorkBudget},
		{"query capacity exhausted", QueryAdmissionLimits{PreparedBytes: 32768, ScanBuffers: 8, Captures: 8}, 1, DefaultQueryWorkBudget},
		{"query work budget exhausted", QueryAdmissionLimits{PreparedBytes: 32768, ScanBuffers: 8, Captures: 8}, 4, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			drain := func() { once.Do(func() { close(release) }) }
			source := &aggregateProbeSource{}
			var holdScan atomic.Bool
			source.hold = func(ctx context.Context, _ PageRequest) error {
				if holdScan.CompareAndSwap(true, false) {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			}

			api := NewWithQueryAdmissionLimits(source, nil, 4096, tc.slots, tc.work, tc.limits)
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := api.Close(ctx); err != nil {
					t.Error(err)
				}
			}()
			server := httptest.NewServer(api)
			defer server.Close()
			if tc.work == 1 {
				aggregateProbeRefusal(t, server.URL, "", tc.name)
				return
			}

			_, cursor := aggregateProbePage(t, api, "", "opening", true)
			middle := strings.Repeat("x", 2500)
			body, next := aggregateProbePage(t, api, cursor, middle, true)
			terminal, _ := aggregateProbePage(t, api, next, "terminal", false)
			if tc.name == "capture count" {
				_, filler := aggregateProbePage(t, api, "", "opening", true)
				aggregateProbeRefusal(t, server.URL, "", tc.name)
				fullBody, fullNext := aggregateProbePage(t, api, cursor, middle, true)
				if fullBody != body || fullNext != next {
					t.Fatal("capture saturation changed an already admitted cursor")
				}
				if err := api.RetireQueryCapture(filler); err != nil {
					t.Fatal(err)
				}
			} else {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				defer drain()
				writer := http.ResponseWriter(httptest.NewRecorder())
				if tc.name == "scan buffers" {
					holdScan.Store(true)
				} else {
					writer = aggregateProbeWriter{httptest.NewRecorder(), func() {
						close(entered)
						<-release
					}}
				}
				go func() {
					defer close(done)
					api.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, aggregateProbeTarget(cursor), nil).WithContext(ctx))
				}()
				select {
				case <-entered:
				case <-done:
					t.Fatal("holding query returned before occupying the resource")
				case <-ctx.Done():
					t.Fatal("holding query did not occupy the resource")
				}
				aggregateProbeRefusal(t, server.URL, cursor, tc.name)
				drain()
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("holding query did not drain")
				}
			}

			retry, retryNext := aggregateProbePage(t, api, cursor, middle, true)
			if retry != body || retryNext != next {
				t.Fatal("retry changed the exact continuation bytes or next cursor")
			}
			retryTerminal, _ := aggregateProbePage(t, api, retryNext, "terminal", false)
			if retryTerminal != terminal {
				t.Fatal("retry changed the exact terminal body")
			}
			if tc.name == "capture count" {
				aggregateProbePage(t, api, "", "opening", true)
			}
		})
	}
}
