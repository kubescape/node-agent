package healthmanager

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kubescape/node-agent/pkg/containerwatcher"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type HealthManager struct {
	containerWatcher containerwatcher.ContainerWatcher
	port             int
}

func NewHealthManager() *HealthManager {
	return &HealthManager{
		port: 7888,
	}
}

func (h *HealthManager) SetContainerWatcher(containerWatcher containerwatcher.ContainerWatcher) {
	h.containerWatcher = containerWatcher
}

func (h *HealthManager) Start(ctx context.Context) {
	go func() {
		srv := h.newServer()
		logger.L().Info("starting health manager", helpers.Int("port", h.port))
		if err := srv.ListenAndServe(); err != nil {
			logger.L().Ctx(ctx).Fatal("HealthManager - failed to start", helpers.Error(err), helpers.Int("port", h.port))
		}
	}()
}

// newServer builds the health server on its own mux, not DefaultServeMux, so
// it serves only the probe endpoints and not handlers other packages register
// globally (such as net/http/pprof).
func (h *HealthManager) newServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", h.livenessProbe)
	mux.HandleFunc("/readyz", h.readinessProbe)
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", h.port),
		Handler:      mux,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
}

func (h *HealthManager) livenessProbe(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *HealthManager) readinessProbe(w http.ResponseWriter, _ *http.Request) {
	if h.containerWatcher != nil && h.containerWatcher.Ready() {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
}
