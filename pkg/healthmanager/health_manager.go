package healthmanager

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kubescape/node-agent/pkg/containerwatcher/v1"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type HealthManager struct {
	containerWatcher *containerwatcher.IGContainerWatcher
	port             int
}

func NewHealthManager() *HealthManager {
	return &HealthManager{
		port: 7888,
	}
}

func (h *HealthManager) SetContainerWatcher(containerWatcher *containerwatcher.IGContainerWatcher) {
	h.containerWatcher = containerWatcher
}

func (h *HealthManager) Start(ctx context.Context) {
	go func() {
		http.HandleFunc("/livez", h.livenessProbe)
		http.HandleFunc("/readyz", h.readinessProbe)
		srv := &http.Server{
			Addr:         fmt.Sprintf(":%d", h.port),
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}
		logger.L().Info("starting health manager", helpers.Int("port", h.port))
		if err := srv.ListenAndServe(); err != nil {
			logger.L().Ctx(ctx).Fatal("failed to start health manager", helpers.Error(err), helpers.Int("port", h.port))
		}
	}()
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
