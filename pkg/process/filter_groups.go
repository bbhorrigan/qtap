package process

import "github.com/qpoint-io/qtap/pkg/config"

func getPredefinedFilters(group string) []config.TapFilter {
	filters, ok := predefinedFilters[group]
	if !ok {
		return nil
	}
	return filters
}

var predefinedFilters = map[string][]config.TapFilter{
	"container-runtimes": {
		// containerd is a container runtime for Linux, written in Go, that is designed to be simple, efficient, and flexible
		{Exe: "/usr/bin/containerd", Strategy: config.MatchStrategy_EXACT},
		// dockerd is the Docker daemon, which is the main process that runs on a Docker host
		{Exe: "/usr/bin/dockerd", Strategy: config.MatchStrategy_EXACT},
		// runc is a CLI tool for spawning and running containers according to the OCI specification
		{Exe: "/usr/bin/runc", Strategy: config.MatchStrategy_EXACT},
	},
	"eks": {
		// AWS Kubernetes Agent (https://github.com/aws/amazon-vpc-cni-k8s/tree/master/cmd/aws-k8s-agent)
		{Exe: "/app/aws-k8s-agent", Strategy: config.MatchStrategy_EXACT},
		// AWS Systems Manager Agent (SSM Agent)
		{Exe: "/usr/bin/amazon-ssm-agent", Strategy: config.MatchStrategy_EXACT},
		// AWS Systems Manager Agent (SSM Agent)
		{Exe: "/usr/bin/ssm-agent-worker", Strategy: config.MatchStrategy_EXACT},
		// AWS Systems Manager Agent (SSM Agent)
		{Exe: "/usr/bin/ssm-document-worker", Strategy: config.MatchStrategy_EXACT},
	},
	"gke": {
		// gcfsd is the GKE Container Storage Interface (CSI) driver for Google Cloud Filestore
		{Exe: "/home/kubernetes/bin/gcfsd", Strategy: config.MatchStrategy_EXACT},
		// event-exporter is a component that runs on Kubernetes nodes to collect and export event data
		{Exe: "/event-exporter", Strategy: config.MatchStrategy_EXACT},
		// fluent-bit-gke-exporter is a component that runs on Kubernetes nodes to collect logs
		{Exe: "/fluent-bit-gke-exporter", Strategy: config.MatchStrategy_EXACT},
		// Node problem detector is a component that runs on Kubernetes nodes to detect and report problems
		{Exe: "/home/kubernetes/bin/node-problem-detector", Strategy: config.MatchStrategy_EXACT},
	},
	"kubernetes": {
		// The kubelet is the primary management agent for containers in a Kubernetes cluster
		{Exe: "/home/kubernetes/bin/kubelet", Strategy: config.MatchStrategy_EXACT},
		// The kube-proxy is a network proxy that runs on each node in a Kubernetes cluster
		{Exe: "/home/kubernetes/bin/kube-proxy", Strategy: config.MatchStrategy_EXACT},
		// The Konnectivity service provides a TCP level proxy for the control plane to cluster communication
		{Exe: "/proxy-agent", Strategy: config.MatchStrategy_EXACT},
		// The cluster proportional autoscaler is a component that watches over the number of schedulable nodes and cores of the cluster and resizes the number of replicas for the required resource
		{Exe: "/cluster-proportional-autoscaler", Strategy: config.MatchStrategy_EXACT},
		// The CSI Node Driver Registrar is a component that registers CSI drivers with the kubelet
		{Exe: "/csi-node-driver-registrar", Strategy: config.MatchStrategy_EXACT},
	},
	"qpoint": {
		// qpoint is the main process that runs on a Qpoint host
		{Exe: "/usr/local/bin/qpoint", Strategy: config.MatchStrategy_EXACT},
	},
}
