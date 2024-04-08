package tests

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	helmclient "github.com/mittwald/go-helm-client"
	"helm.sh/helm/v3/pkg/repo"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	"github.com/testcontainers/testcontainers-go/wait"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/ptr"

	"github.com/armosec/armoapi-go/identifiers"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	spdxv1beta1client "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	apiregistrationclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
)

const (
	kubescapeNamespace = "kubescape"
	namespace          = "default"
	name               = "test"
)

type Test struct {
	ctx        context.Context
	containers map[string]testcontainers.Container
	files      []string
	clusters   []TestKubernetesCluster
}

type TestKubernetesCluster struct {
	ctx           context.Context
	account       string
	cluster       string
	clusterConfig *rest.Config
	k3sC          *k3s.K3sContainer
	k8sclient     kubernetes.Interface
	storageclient *spdxv1beta1client.SpdxV1beta1Client

	// objects
	applicationprofile            *v1beta1.ApplicationProfile
	applicationprofileDesignators identifiers.PortalDesignator
	cm                            *corev1.ConfigMap
	deploy                        *appsv1.Deployment
	sa                            *corev1.ServiceAccount
	secret                        *corev1.Secret
	ss                            *appsv1.StatefulSet
}

func randomPorts(n int) []string {
	lowPort := 32768
	highPort := 61000
	ports := mapset.NewSet[string]()
	for {
		// random port number between lowPort and highPort
		port := strconv.Itoa(rand.Intn(highPort-lowPort+1) + lowPort)
		isFreePort := true
		address := fmt.Sprintf("localhost:%s", port)
		// Trying to listen on the port - cause the port to be in use and it takes some time for the OS to release it,
		// So we need to check if the port is available by trying to connect to it
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if conn != nil {
			conn.Close()
		}
		isFreePort = err != nil // port is available since we got no response
		if isFreePort && !ports.Contains(port) {
			// port is available
			ports.Add(port)
		}
		if ports.Cardinality() > n-1 {
			break
		}
	}
	return ports.ToSlice()
}
func createK8sCluster(t *testing.T, cluster, account string) *TestKubernetesCluster {
	var (
		applicationprofile = &v1beta1.ApplicationProfile{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
				Kind:       "ApplicationProfile",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{{
					Name: "nginx",
					Execs: []v1beta1.ExecCalls{
						{Path: "/usr/sbin/nginx", Args: []string{"-g", "/usr/sbin/nginx", "daemon off;"}},
					},
				}},
			},
		}
		applicationprofileDesignators = identifiers.PortalDesignator{
			Attributes: map[string]string{
				"apiVersion":   "spdx.softwarecomposition.kubescape.io/v1beta1",
				"cluster":      cluster,
				"customerGUID": account,
				"namespace":    namespace,
				"kind":         "ApplicationProfile",
				"name":         name,
				"syncKind":     "spdx.softwarecomposition.kubescape.io/v1beta1/applicationprofiles",
			},
		}
		cm = &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Data: map[string]string{"test": "test"},
		}
		deploy = &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "test"},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "nginx", Image: "nginx"}},
					},
				},
			},
		}
		sa = &corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ServiceAccount",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}
		secret = &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Secret",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}
		ss = &appsv1.StatefulSet{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "StatefulSet",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: appsv1.StatefulSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "test"},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "nginx", Image: "nginx"}},
					},
				},
			},
		}
	)

	ctx := context.TODO()

	// k3s
	k3sC, err := k3s.RunContainer(ctx,
		testcontainers.WithImage("docker.io/rancher/k3s:v1.27.9-k3s1"),
	)
	require.NoError(t, err)
	kubeConfigYaml, err := k3sC.GetKubeConfig(ctx)

	require.NoError(t, err)
	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeConfigYaml)
	require.NoError(t, err)

	k8sclient := kubernetes.NewForConfigOrDie(restConfig)
	helmClient, err := helmclient.NewClientFromRestConf(
		&helmclient.RestConfClientOptions{
			Options: &helmclient.Options{
				Debug: true,
			},
			RestConfig: restConfig,
		},
	)
	require.NoError(t, err)

	helmClient.AddOrUpdateChartRepo(repo.Entry{
		Name: "kubescape",
		URL:  "https://kubescape.github.io/helm-charts",
	})
	chartSpec := helmclient.ChartSpec{
		ReleaseName:     "kubescape",
		ChartName:       "kubescape/kubescape-operator",
		Namespace:       "kubescape",
		Wait:            true,
		CreateNamespace: true,
	}
	helmClient.InstallOrUpgradeChart(ctx, &chartSpec, nil)

	// apiservice
	regclient := apiregistrationclient.NewForConfigOrDie(restConfig)
	_, err = regclient.APIServices().Create(context.TODO(),
		&apiregistrationv1.APIService{
			ObjectMeta: metav1.ObjectMeta{Name: "v1beta1.spdx.softwarecomposition.kubescape.io"},
			Spec: apiregistrationv1.APIServiceSpec{
				InsecureSkipTLSVerify: true,
				Group:                 "spdx.softwarecomposition.kubescape.io",
				GroupPriorityMinimum:  1000,
				VersionPriority:       15,
				Version:               "v1beta1",
				Service: &apiregistrationv1.ServiceReference{
					Name:      "storage",
					Namespace: "kubescape",
				},
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// kubescape namespace
	_, err = k8sclient.CoreV1().Namespaces().Create(context.TODO(),
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "kubescape"},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// storage service
	storageLabels := map[string]string{"app.kubernetes.io/name": "storage"}
	_, err = k8sclient.CoreV1().Services("kubescape").Create(context.TODO(),
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "storage"},
			Spec: corev1.ServiceSpec{
				Ports:    []corev1.ServicePort{{Port: 443, Protocol: "TCP", TargetPort: intstr.FromInt32(8443)}},
				Selector: storageLabels,
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// storage configmap
	_, err = k8sclient.CoreV1().ConfigMaps("kubescape").Create(context.TODO(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "ks-cloud-config"},
			Data: map[string]string{
				"clusterData": `{"clusterName":"k3s"}`,
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// storage serviceaccount
	_, err = k8sclient.CoreV1().ServiceAccounts("kubescape").Create(context.TODO(),
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "storage"},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// storage rolebinding
	_, err = k8sclient.RbacV1().RoleBindings("kube-system").Create(context.TODO(),
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "storage-auth-reader"},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "extension-apiserver-authentication-reader",
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      "storage",
				Namespace: "kubescape",
			}},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// storage clusterrole
	_, err = k8sclient.RbacV1().ClusterRoles().Create(context.TODO(),
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "storage"},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get", "watch", "list"}},
				{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}, Verbs: []string{"get", "watch", "list"}},
				{APIGroups: []string{"flowcontrol.apiserver.k8s.io"}, Resources: []string{"prioritylevelconfigurations", "flowschemas"}, Verbs: []string{"get", "watch", "list"}},
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// storage clusterrolebinding
	_, err = k8sclient.RbacV1().ClusterRoleBindings().Create(context.TODO(),
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "storage"},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "storage",
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      "storage",
				Namespace: "kubescape",
			}},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// storage clusterrolebinding 2
	_, err = k8sclient.RbacV1().ClusterRoleBindings().Create(context.TODO(),
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "storage:system:auth-delegator"},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "system:auth-delegator",
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      "storage",
				Namespace: "kubescape",
			}},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// storage deployment
	_, err = k8sclient.AppsV1().Deployments("kubescape").Create(context.TODO(),
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "storage", Labels: storageLabels},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{MatchLabels: storageLabels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: storageLabels},
					Spec: corev1.PodSpec{
						ServiceAccountName: "storage",
						SecurityContext: &corev1.PodSecurityContext{
							RunAsUser: ptr.To(int64(65532)),
							FSGroup:   ptr.To(int64(65532)),
						},
						Containers: []corev1.Container{{
							Name:  "apiserver",
							Image: "quay.io/kubescape/storage:v0.0.69",
							VolumeMounts: []corev1.VolumeMount{
								{Name: "data", MountPath: "/data"},
								{Name: "ks-cloud-config", MountPath: "/etc/config"},
							},
						}},
						Volumes: []corev1.Volume{
							{Name: "data", VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							}},
							{Name: "ks-cloud-config", VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: "ks-cloud-config"},
									Items: []corev1.KeyToPath{
										{Key: "clusterData", Path: "clusterData.json"},
									},
								},
							}},
						},
					},
				},
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)

	kubernetesCluster := &TestKubernetesCluster{
		account:                       account,
		cluster:                       cluster,
		ctx:                           ctx,
		clusterConfig:                 restConfig,
		k3sC:                          k3sC,
		k8sclient:                     k8sclient,
		applicationprofile:            applicationprofile,
		applicationprofileDesignators: applicationprofileDesignators,
		cm:                            cm,
		deploy:                        deploy,
		sa:                            sa,
		secret:                        secret,
		ss:                            ss,
	}
	waitForStorage(t, kubernetesCluster)
	return kubernetesCluster
}

func waitForStorage(t *testing.T, cluster *TestKubernetesCluster) {
	// wait until storage is ready
	storageclient := spdxv1beta1client.NewForConfigOrDie(cluster.clusterConfig)
	cluster.storageclient = storageclient

	err := backoff.RetryNotify(func() error {
		_, err := storageclient.ApplicationProfiles(namespace).Create(context.TODO(), cluster.applicationprofile, metav1.CreateOptions{})
		return err
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(5*time.Second), 20), func(err error, d time.Duration) {
		logger.L().Info("waiting for storage to be ready", helpers.Error(err), helpers.String("retry in", d.String()))
	})
	require.NoError(t, err)
	// cleanup
	err = storageclient.ApplicationProfiles(namespace).Delete(context.TODO(), cluster.applicationprofile.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
}

func createPulsar(t *testing.T, ctx context.Context, brokerPort, adminPort string) (pulsarC testcontainers.Container, pulsarUrl, pulsarAdminUrl string) {
	pulsarC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "apachepulsar/pulsar:2.11.0",
			Cmd:          []string{"bin/pulsar", "standalone"},
			ExposedPorts: []string{brokerPort + ":6650/tcp", adminPort + ":8080/tcp"},
			WaitingFor: wait.ForAll(
				wait.ForExposedPort(),
				wait.ForHTTP("/admin/v2/clusters").WithPort("8080/tcp").WithResponseMatcher(func(r io.Reader) bool {
					respBytes, _ := io.ReadAll(r)
					resp := string(respBytes)
					return strings.Contains(resp, `["standalone"]`)
				}),
			),
		},
		Started: true,
	})
	require.NoError(t, err)
	pulsarUrl, err = pulsarC.PortEndpoint(ctx, "6650", "pulsar")
	require.NoError(t, err)
	pulsarAdminUrl, err = pulsarC.PortEndpoint(ctx, "8080", "http")
	require.NoError(t, err)
	return pulsarC, pulsarUrl, pulsarAdminUrl
}

func initIntegrationTest(t *testing.T) *Test {
	ctx := context.TODO()

	err := logger.L().SetLevel(helpers.DebugLevel.String())
	require.NoError(t, err)

	// create k8s cluster
	cluster_1 := createK8sCluster(t, "cluster1", "b486ba4e-ffaa-4cd4-b885-b6d26cd13193")
	cluster_2 := createK8sCluster(t, "cluster2", "0757d22d-a9c1-4ca3-87b6-f2236f7f5885")

	// generate some random ports
	// pulsar, pulsar-admin, postgres, sync1, sync2, sync-http1, sync-http2
	ports := randomPorts(7)
	// pulsar
	_, _, _ = createPulsar(t, ctx, ports[0], ports[1])

	time.Sleep(10 * time.Second)
	return &Test{
		ctx: ctx,
		containers: map[string]testcontainers.Container{
			"k3s1": cluster_1.k3sC,
			"k3s2": cluster_2.k3sC,
		},
		clusters: []TestKubernetesCluster{*cluster_1, *cluster_2},
	}
}

func tearDown(td *Test) {
	for _, c := range td.containers {
		_ = c.Terminate(td.ctx)
	}
	for _, f := range td.files {
		_ = os.Remove(f)
	}
}

// TestSynchronizer_TC01_Backend: Initial synchronization of a single entity
func TestNodeAgent_TC01(t *testing.T) {
	td := initIntegrationTest(t)
	// add cm to backend via pulsar message
	// pulsarProducer, err := eventingester.NewPulsarProducer(td.pulsarClient, "synchronizer")
	// require.NoError(t, err)
	// bytes, err := json.Marshal(td.clusters[0].cm)
	// require.NoError(t, err)
	// err = pulsarProducer.SendPutObjectMessage(td.ctx, td.clusters[0].account, td.clusters[0].cluster, "/v1/configmaps", namespace, name, "", 0, bytes)
	// require.NoError(t, err)
	time.Sleep(10 * time.Second)
	// check object in k8s
	k8sCm, err := td.clusters[0].k8sclient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "test", k8sCm.Data["test"])
	// tear down
	tearDown(td)
}

// TestSynchronizer_TC02_InCluster: Delta synchronization of a single entity
func TestNodeAgent_TC02(t *testing.T) {
	td := initIntegrationTest(t)
	// add applicationprofile to k8s
	_, err := td.clusters[0].storageclient.ApplicationProfiles(namespace).Create(context.TODO(), td.clusters[0].applicationprofile, metav1.CreateOptions{})
	require.NoError(t, err)

	time.Sleep(10 * time.Second)
	// modify applicationprofile in k8s
	k8sAppProfile, err := td.clusters[0].storageclient.ApplicationProfiles(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	require.NoError(t, err)
	k8sAppProfile.Spec.Containers[0].Name = "nginx2"
	_, err = td.clusters[0].storageclient.ApplicationProfiles(namespace).Update(context.TODO(), k8sAppProfile, metav1.UpdateOptions{})
	require.NoError(t, err)

	// tear down
	tearDown(td)
}
func getPodNamesInNamespace(k8sClient kubernetes.Interface, namespace string) []string {
	podNames := []string{}
	pods, err := k8sClient.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return podNames
	}

	for _, pod := range pods.Items {
		podNames = append(podNames, pod.Name)
	}
	return podNames
}
