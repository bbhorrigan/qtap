package container

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	DefaultDockerHostEnv    = "DOCKER_HOST"
	DefaultDockerSocketPath = "unix:///var/run/docker.sock"
)

type Action string

const (
	ActionCreate Action = "create"
	ActionStart  Action = "start"

	ActionExecCreate Action = "exec_create"
	ActionExecStart  Action = "exec_start"
)

type docker struct {
	logger *zap.Logger
	mu     sync.RWMutex
	client *client.Client
	cache  map[string]*Container // TODO: convert to our own map
}

func NewDockerAccessor(logger *zap.Logger, endpoint string) (*docker, error) {
	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}

	if endpoint != "" {
		opts = append(opts, client.WithHost(endpoint))
	} else if os.Getenv(DefaultDockerHostEnv) == "" {
		opts = append(opts, client.WithHost(DefaultDockerSocketPath))
	}

	c, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.TODO(), DefaultStartupTimeout)
	defer cancel()
	if _, err := c.Info(ctx); err != nil {
		return nil, err
	}

	return &docker{
		logger: logger,
		client: c,
		cache:  make(map[string]*Container),
	}, nil
}

func (d *docker) Start(ctx context.Context) error {
	containers, err := d.client.ContainerList(ctx, containertypes.ListOptions{
		Filters: filters.NewArgs(filters.Arg("status", "running")),
	})
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	for _, cr := range containers {
		d.handleContainerEvent(ctx, cr.ID)
	}

	go func() {
		d.watchContainerEventsWithRetry(ctx)
	}()

	return nil
}

func (d *docker) GetByID(containerID string) *Container {
	if containerID == "" {
		return nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	containerID = humanContainerID(containerID)

	return d.cache[containerID]
}

func (d *docker) Close() error {
	return d.client.Close()
}

func (d *docker) handleContainerEvent(ctx context.Context, containerID string) {
	cr, err := d.inspectContainer(ctx, containerID)
	if err != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.cache[humanContainerID(cr.ID)] = cr
}

func (d *docker) inspectContainer(ctx context.Context, containerID string) (*Container, error) {
	c := d.client

	data, err := c.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("inspect container %s: %w", containerID, err)
	}

	cr := &Container{
		ID:          containerID,
		Name:        data.Name,
		ImageDigest: data.Image,
	}
	if conf := data.Config; conf != nil {
		cr.Image = conf.Image
		cr.Labels = conf.Labels
	}
	if state := data.State; state != nil && state.Pid != 0 {
		cr.RootPID = state.Pid
	}

	// extract RootFS path from GraphDriver data
	if data.GraphDriver.Data != nil {
		if mergedDir, ok := data.GraphDriver.Data["MergedDir"]; ok {
			cr.RootFS = mergedDir
		}
	}

	return cr, nil
}

func (d *docker) watchContainerEventsWithRetry(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		d.watchContainerEvents(ctx)

		time.Sleep(DefaultWatchInterval)
	}
}

func (d *docker) watchContainerEvents(ctx context.Context) {
	c := d.client

	var chMsg <-chan events.Message
	var chErr <-chan error
	var msg events.Message

	chMsg, chErr = c.Events(ctx, events.ListOptions{})

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-chErr:
			if errors.Is(err, context.Canceled) {
				return
			}
			return
		case msg = <-chMsg:
		}

		if msg.Type != events.ContainerEventType {
			continue
		}
		if string(msg.Action) == string(ActionStart) ||
			strings.HasPrefix(string(msg.Action), string(ActionExecCreate)+": ") ||
			strings.HasPrefix(string(msg.Action), string(ActionExecStart)+": ") {
			d.handleContainerEvent(ctx, msg.Actor.ID)
		}
	}
}
