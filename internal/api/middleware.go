package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/pkg/jcs"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxTraceID
	ctxClientIP
)

func requestID(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}

func clientIP(ctx context.Context) string {
	v, _ := ctx.Value(ctxClientIP).(string)
	return v
}

var (
	requestIDPattern   = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	traceparentPattern = regexp.MustCompile(`^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// middleware wraps the router with request ids, client IP resolution,
// security headers, CORS, panic recovery, structured logging and metrics.
// Logs never include request or response bodies, credentials or event data.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get("X-Request-Id")
		if !requestIDPattern.MatchString(reqID) {
			reqID = id.New("req")
		}
		ctx := withPrincipalHolder(context.WithValue(r.Context(), ctxRequestID, reqID))
		if m := traceparentPattern.FindStringSubmatch(r.Header.Get("traceparent")); m != nil {
			ctx = context.WithValue(ctx, ctxTraceID, m[1])
		}
		ip := s.resolveClientIP(r)
		ctx = context.WithValue(ctx, ctxClientIP, ip)
		r = r.WithContext(ctx)

		h := w.Header()
		h.Set("X-Request-Id", reqID)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		if s.cors(w, r) {
			return
		}

		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic", "request_id", reqID, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				if rec.status == 0 {
					s.writeError(rec, r, fmt.Errorf("panic: %v", p))
				}
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			elapsed := time.Since(start)
			if s.metrics != nil {
				s.metrics.APIRequests.WithLabelValues(r.Method, route, strconv.Itoa(status)).Inc()
				s.metrics.APIDuration.WithLabelValues(r.Method, route).Observe(elapsed.Seconds())
			}
			attrs := []slog.Attr{
				slog.String("request_id", reqID), slog.String("method", r.Method), slog.String("route", route),
				slog.Int("status", status), slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000),
				slog.Int64("bytes", rec.bytes), slog.String("client_ip", ip),
			}
			if t, ok := ctx.Value(ctxTraceID).(string); ok {
				attrs = append(attrs, slog.String("trace_id", t))
			}
			if p := principalFrom(r); p != nil {
				attrs = append(attrs, slog.String("principal", p.Actor()))
			}
			level := slog.LevelInfo
			if status >= 500 {
				level = slog.LevelError
			} else if route == "GET /health" || route == "GET /ready" || route == "GET /metrics" {
				level = slog.LevelDebug
			}
			s.log.LogAttrs(ctx, level, "request", attrs...)
		}()
		next.ServeHTTP(rec, r)
	})
}

// cors answers preflight requests for allowed origins. CORS is disabled
// unless DELIL_CORS_ALLOWED_ORIGINS lists origins; API keys must never be
// embedded in browser code, so most deployments leave it off.
func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || !s.corsOrigins[origin] {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Expose-Headers", "X-Request-Id, Idempotent-Replayed, Retry-After")
	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, Delil-Project, X-Request-Id")
		h.Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// resolveClientIP uses X-Forwarded-For only when the direct peer is a trusted
// proxy, taking the right-most address that is not itself trusted.
func (s *Server) resolveClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !s.trusted(peer) {
		return peer.String()
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.trusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// readBody reads a JSON request body within the size limit.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	ct := r.Header.Get("Content-Type")
	media, _, err := mime.ParseMediaType(ct)
	if err != nil || media != "application/json" {
		return nil, errorf(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, badRequest("request body is empty")
	}
	return body, nil
}

// decodeJSON parses a body strictly (valid UTF-8, no duplicate members) into
// v, rejecting unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	body, err := readBody(w, r, limit)
	if err != nil {
		return err
	}
	if _, err := jcs.ParseWithOptions(body, jcs.Options{MaxDepth: 32, DisallowNUL: true}); err != nil {
		return badRequest("invalid JSON: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid request body: %v", err)
	}
	return nil
}

// writeJSON writes v without HTML escaping, so canonical content in chain
// records is transmitted byte for byte.
func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, `{"error":{"code":"internal_error","message":"response encoding failed"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
