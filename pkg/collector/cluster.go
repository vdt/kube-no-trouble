package collector

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/restmapper"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

type ClusterCollector struct {
	*commonCollector
	clientSet           dynamic.Interface
	discoveryClient     discovery.DiscoveryInterface
	additionalResources []schema.GroupVersionResource
}

type ClusterOpts struct {
	Kubeconfig      string
	ClientSet       dynamic.Interface
	DiscoveryClient discovery.DiscoveryInterface
}

func NewClusterCollector(opts *ClusterOpts, additionalKinds []string) (*ClusterCollector, error) {
	collector := &ClusterCollector{commonCollector: &commonCollector{name: "Cluster"}}

	if opts.ClientSet == nil {
		config, err := clientcmd.BuildConfigFromFlags("", opts.Kubeconfig)
		if err != nil {
			return nil, err
		}

		collector.clientSet, err = dynamic.NewForConfig(config)
		if err != nil {
			return nil, err
		}

	} else {
		collector.clientSet = opts.ClientSet
	}

	if opts.DiscoveryClient == nil {
		config, err := clientcmd.BuildConfigFromFlags("", opts.Kubeconfig)
		if err != nil {
			return nil, err
		}

		collector.discoveryClient, err = discovery.NewDiscoveryClientForConfig(config)
		if err != nil {
			return nil, err
		}
	} else {
		collector.discoveryClient = opts.DiscoveryClient
	}

	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(collector.discoveryClient))
	for _, ar := range additionalKinds {
		gvk, _ := schema.ParseKindArg(ar)

		gvrMap, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			log.Warn().Msgf("Failed to map %s Kind to resource: %s", gvk.Kind, err)
			continue
		}

		collector.additionalResources = append(collector.additionalResources, gvrMap.Resource)
	}

	return collector, nil
}

func (c *ClusterCollector) Get() ([]map[string]interface{}, error) {
	gvrs := []schema.GroupVersionResource{
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"},
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"},
		schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
		schema.GroupVersionResource{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"},
		schema.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "ingresses"},
	}
	gvrs = append(gvrs, c.additionalResources...)

	var results []map[string]interface{}
	for _, g := range gvrs {
		ri := c.clientSet.Resource(g)
		log.Debug().Msgf("Retrieving: %s.%s.%s", g.Resource, g.Version, g.Group)
		rs, err := ri.List(metav1.ListOptions{})
		if err != nil {
			log.Warn().Msgf("Failed to retrieve: %s: %s", g, err)
			continue
		}

		for _, r := range rs.Items {
			if jsonManifest, ok := r.GetAnnotations()["kubectl.kubernetes.io/last-applied-configuration"]; ok {
				var manifest map[string]interface{}

				err := json.Unmarshal([]byte(jsonManifest), &manifest)
				if err != nil {
					err := fmt.Errorf("failed to parse 'last-applied-configuration' annotation of resource %s/%s: %v", r.GetNamespace(), r.GetName(), err)
					return nil, err
				}
				results = append(results, manifest)
			}
		}
	}

	return results, nil
}
