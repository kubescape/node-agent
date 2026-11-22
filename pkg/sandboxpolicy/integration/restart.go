package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// restartPinDir is the directory of the pinned enforcement sets on the host bpffs.
const restartPinDir = "kubescape-sandbox"

// RestartPinRoot returns the directory for pinned enforcement on the host
// bpffs, or "" when node-agent sees no host bpffs. Only the host root is used:
// the container's own /sys/fs/bpf can be a bpffs that node-agent mounted
// itself (validator workaroundMounts), and that one ends with the container.
func RestartPinRoot() string {
	dir := filepath.Join(host.HostRoot, "sys/fs/bpf")
	if !enforcement.IsBPFFS(dir) {
		return ""
	}
	return filepath.Join(dir, restartPinDir)
}

// RemoveRestartPins removes every pinned enforcement set. Call it when the
// sandbox policy feature is off, so a previous run's sets do not stay.
func RemoveRestartPins() error {
	root := RestartPinRoot()
	if root == "" {
		return nil
	}
	return igbackend.RemoveRestartPins(root)
}

// removeRestartPins is RemoveRestartPins (replaced in tests).
var removeRestartPins = RemoveRestartPins

type restartSurvivor interface {
	RestartSurvival(root string) error
}

// restartSection is one section at start: its backend (nil: not loaded) and
// whether its image is set (unset: the section is off).
type restartSection struct {
	backend    sandboxpolicy.Backend
	configured bool
}

// removeSectionPins is igbackend.RemoveRestartPins (replaced in tests).
var removeSectionPins = igbackend.RemoveRestartPins

// enableRestartSurvival turns on restart survival for the node backends that
// run, and removes the pinned sets of the sections that are off (no image).
// A section that is configured but unavailable (a failed host check) keeps
// its pinned sets: their links may still enforce. It returns those sections
// that kept pinned sets, so their status can say so.
func enableRestartSurvival(sections map[string]restartSection, report func(error)) map[string]bool {
	root := RestartPinRoot()
	if root == "" {
		logger.L().Warning("sandbox restart survival off: no host bpffs", helpers.String("path", filepath.Join(host.HostRoot, "sys/fs/bpf")))
		return nil
	}
	return enableRestartSurvivalAt(root, sections, report)
}

func enableRestartSurvivalAt(root string, sections map[string]restartSection, report func(error)) map[string]bool {
	kept := map[string]bool{}
	for section, sec := range sections {
		if sec.backend == nil {
			if sec.configured {
				if entries, err := os.ReadDir(filepath.Join(root, section)); err != nil && !errors.Is(err, os.ErrNotExist) || len(entries) > 0 {
					logger.L().Warning("sandbox section unavailable: its pinned sets are kept", helpers.String("section", section))
					kept[section] = true
				}
				continue
			}
			if err := removeSectionPins(root, section); err != nil {
				report(fmt.Errorf("removing %s restart pins: %w", section, err))
			}
			continue
		}
		survivor, ok := sec.backend.(restartSurvivor)
		if !ok {
			continue
		}
		if err := survivor.RestartSurvival(root); err != nil {
			report(fmt.Errorf("%s restart survival: %w", section, err))
			continue
		}
		logger.L().Info("sandbox restart survival on", helpers.String("section", section), helpers.String("root", root))
	}
	return kept
}

// keptPins adds to an unavailable section's error that the previous run's
// pinned sets were kept.
func keptPins(unavailable error, kept bool) error {
	if unavailable == nil || !kept {
		return unavailable
	}
	return fmt.Errorf("%w; the pinned sets of the previous node-agent run are kept and may still enforce", unavailable)
}

// uninstallReadTimeout bounds the fresh DaemonSet read at shutdown.
const uninstallReadTimeout = 2 * time.Second

// ownerReadTimeout bounds the read of node-agent's own pod when the watch
// starts (a variable for tests).
var ownerReadTimeout = 10 * time.Second

// daemonSetWatch follows node-agent's own DaemonSet while node-agent runs, so
// shutdown can tell an uninstall (helm uninstall, kubectl delete: the
// DaemonSet is gone or being deleted, no next node-agent takes the pinned
// sets over, so they must not keep enforcing with no owner until the next
// reboot) from a restart (a rolling update, an eviction or a crash keeps the
// DaemonSet, so the pins stay). It decides before the backend closes: by then
// an uninstall may have removed node-agent's RBAC, and a read would fail.
type daemonSetWatch struct {
	client          kubernetes.Interface
	namespace, name string
	// uid is the DaemonSet that owns this pod. A DaemonSet recreated under
	// the same name (kubectl replace --force, a GitOps replace) has another
	// UID; it starts a node-agent that takes the pins over.
	uid      types.UID
	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	cancel   context.CancelFunc

	mu       sync.Mutex
	present  bool // the cache holds a DaemonSet of that name
	deleting bool // ... with this pod's owner UID, being deleted
	other    bool // ... with another UID (recreated)
}

// ownDaemonSet finds the DaemonSet that owns the pod. It returns nil when the
// pod has no DaemonSet owner.
func ownDaemonSet(ctx context.Context, client kubernetes.Interface, namespace, pod string) (*daemonSetWatch, error) {
	if client == nil || namespace == "" || pod == "" {
		return nil, fmt.Errorf("no pod identity to follow the DaemonSet")
	}
	p, err := client.CoreV1().Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	for _, owner := range p.OwnerReferences {
		if owner.Kind == "DaemonSet" {
			return &daemonSetWatch{client: client, namespace: namespace, name: owner.Name, uid: owner.UID}, nil
		}
	}
	return nil, nil
}

// watchOwnDaemonSet starts following the DaemonSet that owns the pod. It
// returns nil when the pod has no DaemonSet owner.
func watchOwnDaemonSet(ctx context.Context, client kubernetes.Interface, namespace, pod string) (*daemonSetWatch, error) {
	// Bounded: Start waits for it. Without a watch, shutdown still reads
	// once (decideUninstall).
	readCtx, cancel := context.WithTimeout(ctx, ownerReadTimeout)
	w, err := ownDaemonSet(readCtx, client, namespace, pod)
	cancel()
	if w == nil || err != nil {
		return nil, err
	}
	w.factory = informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithNamespace(namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.FieldSelector = "metadata.name=" + w.name }))
	w.informer = w.factory.Apps().V1().DaemonSets().Informer()
	if _, err := w.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.observe(obj, false) },
		UpdateFunc: func(_, obj any) { w.observe(obj, false) },
		DeleteFunc: func(obj any) { w.observe(obj, true) },
	}); err != nil {
		return nil, err
	}
	watchCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.factory.Start(watchCtx.Done())
	return w, nil
}

func (w *daemonSetWatch) observe(obj any, deleted bool) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	ds, ok := obj.(*appsv1.DaemonSet)
	if !ok || ds.Name != w.name {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.present = !deleted
	w.other = !deleted && ds.UID != w.uid
	w.deleting = !deleted && ds.UID == w.uid && ds.DeletionTimestamp != nil
}

// cached is the decision from the watch: known is false until the watch
// listed the DaemonSet once.
func (w *daemonSetWatch) cached() (gone, known bool) {
	if w.informer == nil || !w.informer.HasSynced() {
		return false, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.present || w.deleting, true
}

// uninstalling decides at shutdown: one fresh read (at most
// uninstallReadTimeout), else the watch. When neither is known, the answer is
// "not uninstalling": keeping the pins fails closed.
func (w *daemonSetWatch) uninstalling(ctx context.Context) bool {
	readCtx, cancel := context.WithTimeout(ctx, uninstallReadTimeout)
	defer cancel()
	ds, err := w.client.AppsV1().DaemonSets(w.namespace).Get(readCtx, w.name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return true
	case err == nil:
		return ds.UID == w.uid && ds.DeletionTimestamp != nil
	}
	gone, known := w.cached()
	logger.L().Warning("sandbox shutdown: DaemonSet read failed; using the watched state",
		helpers.Error(err), helpers.String("daemonset", w.name), helpers.String("uninstalling", fmt.Sprint(known && gone)))
	return known && gone
}

func (w *daemonSetWatch) stop() {
	if w != nil && w.factory != nil {
		w.cancel() // Shutdown waits for the informer, which stops on this
		w.factory.Shutdown()
	}
}

// decideUninstall decides once, at the start of shutdown, whether node-agent
// stops for an uninstall. Without a watch (it could not start) it resolves
// the DaemonSet now, within uninstallReadTimeout.
func (s *Service) decideUninstall(ctx context.Context) {
	if s.uninstallDecided || RestartPinRoot() == "" {
		return
	}
	s.uninstallDecided = true
	s.mu.Lock()
	w := s.dsWatch
	s.mu.Unlock()
	if w == nil {
		readCtx, cancel := context.WithTimeout(ctx, uninstallReadTimeout)
		var err error
		w, err = ownDaemonSet(readCtx, s.options.Kubernetes, s.options.AgentNamespace, s.options.PodName)
		cancel()
		if err != nil {
			s.report(fmt.Errorf("checking for an uninstall at shutdown (the pinned sets stay): %w", err))
		}
		if w == nil {
			return
		}
	}
	s.uninstall = w.uninstalling(ctx)
}

// removePinsOnUninstall removes every pinned enforcement set, and the
// sections' state map pins, when shutdown found an uninstall
// (decideUninstall). It runs once, after the refresh loop joined.
func (s *Service) removePinsOnUninstall() {
	s.mu.Lock()
	w := s.dsWatch
	s.mu.Unlock()
	w.stop()
	if !s.uninstall || s.pinsRemoved {
		return
	}
	s.pinsRemoved = true
	logger.L().Info("sandbox DaemonSet deleted: removing the pinned enforcement sets")
	if err := removeRestartPins(); err != nil {
		s.report(fmt.Errorf("removing the pinned sets after an uninstall: %w", err))
	}
}
