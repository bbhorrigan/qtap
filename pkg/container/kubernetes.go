package container

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	cri "k8s.io/cri-api/pkg/apis"
	remote "k8s.io/cri-client/pkg"
)

var DefaultRuntimeEndpoints = []string{
	"unix:///var/run/dockershim.sock",
	"unix:///var/run/cri-dockerd.sock",
	"unix:///run/crio/crio.sock",
	"unix:///run/containerd/containerd.sock",
}

type KubernetesAccessor struct {
	logger *zap.Logger
	rs     cri.RuntimeService
}

func NewKubernetesAccessor(logger *zap.Logger, criRuntimeEndpoint string) (*KubernetesAccessor, string, []error) {
	rs, endpoint, errs := getRuntimeService(logger, criRuntimeEndpoint)
	if len(errs) > 0 {
		return nil, "", errs
	}

	return &KubernetesAccessor{logger: logger, rs: rs}, endpoint, nil
}

func (m *KubernetesAccessor) AddPodToContainer(c *Container) *Container {
	// get the pod from the container
	p := c.Pod()

	// if we have k8s runtime services, get extended pod information
	if m.rs != nil {
		tmp := m.getPodByName(context.TODO(), p.Name, p.Namespace)
		p.Labels = tmp.Labels
		p.Annotations = tmp.Annotations

		c.SetPod(p)
	}

	return c
}

func (m *KubernetesAccessor) getPodByName(ctx context.Context, name, namespace string) (p Pod) {
	if m.rs == nil {
		return
	}

	sandboxes, err := m.rs.ListPodSandbox(ctx, nil)
	if err != nil {
		m.logger.Warn("list pod sandbox failed", zap.Error(err))

		return
	}

	for _, sandbox := range sandboxes {
		if sandbox.Metadata.Name != name || sandbox.Metadata.Namespace != namespace {
			continue
		}
		p.Labels = tidyLabels(sandbox.Labels)
		p.Annotations = sandbox.Annotations
		break
	}

	return p
}

func tidyLabels(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return raw
	}

	newLabels := make(map[string]string)
	for k, v := range raw {
		if k == ContainerLabelKeyPodName ||
			k == ContainerLabelKeyPodNamespace ||
			k == ContainerLabelKeyPodUID {
			continue
		}
		newLabels[k] = v
	}

	return newLabels
}

func getRuntimeService(logger *zap.Logger, criRuntimeEndpoint string) (rs cri.RuntimeService, endpoint string, errs []error) {
	endpoints := DefaultRuntimeEndpoints
	if criRuntimeEndpoint != "" {
		endpoints = []string{criRuntimeEndpoint}
	}

	for _, e := range endpoints {
		var err error
		logger.Debug("attempting to connect to runtime service", zap.String("endpoint", e))

		rs, err = remote.NewRemoteRuntimeService(e, DefaultRuntimeTimeout, nil, nil)
		if err != nil {
			if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file or directory") {
				err = errors.New("no such file or directory")
			}
			errs = append(errs, fmt.Errorf("connect using endpoint %s: %w", e, err))
			continue
		}

		endpoint = e

		if _, err1 := rs.Version(context.TODO(), string(remote.CRIVersionV1)); err1 != nil {
			logger.Debug("check version failed", zap.String("version", string(remote.CRIVersionV1)), zap.Error(err1))
			errs = append(errs, fmt.Errorf("using endpoint %s failed: %w", e, err1))
			rs = nil
			continue
		}

		errs = nil
		break
	}

	return rs, endpoint, errs
}
