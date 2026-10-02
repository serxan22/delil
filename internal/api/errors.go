package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/export"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/store"
)

// Error is an API error rendered as
// {"error": {"code": ..., "message": ..., "requestId": ..., "details": ...}}.
type Error struct {
	Status     int
	Code       string
	Message    string
	Details    any
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errorf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

func badRequest(format string, args ...any) *Error {
	return errorf(http.StatusBadRequest, "invalid_request", format, args...)
}

func notFound(what string) *Error {
	return errorf(http.StatusNotFound, "not_found", "%s not found", what)
}

func forbidden(format string, args ...any) *Error {
	return errorf(http.StatusForbidden, "forbidden", format, args...)
}

func unauthorized(msg string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: "unauthorized", Message: msg}
}

// toAPIError maps internal errors to API errors. Unknown errors become a
// generic 500 whose details are only logged.
func toAPIError(err error) (*Error, bool) {
	var apiErr *Error
	var ve *audit.ValidationError
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &apiErr):
		return apiErr, true
	case errors.As(err, &ve):
		return &Error{Status: http.StatusUnprocessableEntity, Code: "invalid_event",
			Message: "the event failed validation", Details: map[string]any{"errors": ve.Errors}}, true
	case errors.As(err, &mbe):
		return errorf(http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds %d bytes", mbe.Limit), true
	case errors.Is(err, store.ErrNotFound):
		return notFound("resource"), true
	case errors.Is(err, audit.ErrEventTooLarge):
		return errorf(http.StatusRequestEntityTooLarge, "event_too_large", "%v", err), true
	case errors.Is(err, audit.ErrIdempotencyMismatch):
		return errorf(http.StatusUnprocessableEntity, "idempotency_key_reused",
			"this Idempotency-Key was already used for a different request"), true
	case errors.Is(err, audit.ErrTooManyStreams):
		return errorf(http.StatusUnprocessableEntity, "stream_limit_reached", "%v", err), true
	case errors.Is(err, export.ErrInvalidParams):
		return errorf(http.StatusBadRequest, "invalid_request", "%v", err), true
	case errors.Is(err, export.ErrNotReady):
		return errorf(http.StatusConflict, "export_not_ready", "the export is not completed"), true
	case errors.Is(err, keys.ErrNoActiveKey):
		return errorf(http.StatusConflict, "no_active_signing_key", "the project has no active signing key"), true
	case errors.Is(err, context.Canceled):
		return errorf(499, "client_closed_request", "the client closed the request"), true
	case errors.Is(err, context.DeadlineExceeded):
		return errorf(http.StatusServiceUnavailable, "timeout", "the operation timed out"), true
	case errors.Is(err, store.ErrConflict):
		return errorf(http.StatusConflict, "conflict", "the resource already exists"), true
	}
	return &Error{Status: http.StatusInternalServerError, Code: "internal_error",
		Message: "an internal error occurred; quote the request id when reporting it"}, false
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr, known := toAPIError(err)
	if !known {
		s.log.Error("request failed", "request_id", requestID(r.Context()), "route", r.Pattern, "error", err)
	}
	if apiErr.RetryAfter > 0 {
		secs := int(apiErr.RetryAfter.Seconds() + 0.999)
		w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
	}
	body := map[string]any{
		"code":      apiErr.Code,
		"message":   apiErr.Message,
		"requestId": requestID(r.Context()),
	}
	if apiErr.Details != nil {
		body["details"] = apiErr.Details
	}
	status := apiErr.Status
	if status == 499 {
		status = http.StatusBadRequest // never sent: the client is gone
	}
	writeJSON(w, status, map[string]any{"error": body})
}
