package controllers

import (
	"context"
	"fmt"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	encryptiondeployer "github.com/openshift/library-go/pkg/operator/encryption/deployer"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/google/go-cmp/cmp"
)

func fakePodTemplateBuilderFunc(targetHash, targetNamespace, image, keyID, region, listen string) (string, error) {
	return fmt.Sprintf(
		"targetHash: %s\ntargetNamespace: %s\nimage: %s\nkeyID: %s\nregion: %s\nlisten: %s\n",
		targetHash, targetNamespace, image, keyID, region, listen,
	), nil
}

func constantFakePodTemplateBuilderFunc(targetHash, targetNamespace, image, keyID, region, listen string) (string, error) {
	return "test-pod-manifest", nil
}

func TestKMSPluginController(t *testing.T) {
	testCases := []struct {
		name            string
		targetNamespace string
		managementState operatorv1.ManagementState
		apiserverConfig *configv1.APIServer
		initialObjects  []runtime.Object
		syncError       error
	}{
		{
			name:            "operator managed and kms plugin correctly configured",
			targetNamespace: "openshift-apiserver",
			managementState: operatorv1.Managed,
			apiserverConfig: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					Encryption: configv1.APIServerEncryption{
						Type: configv1.EncryptionTypeKMS,
						KMS: &configv1.KMSConfig{
							Type: configv1.AWSKMSProvider,
							AWS: &configv1.AWSKMSConfig{
								Region: "us-east-1",
								KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
							},
						},
					},
				},
			},
		},
		{
			name:            "operator managed and encryption not configured",
			targetNamespace: "openshift-apiserver",
			managementState: operatorv1.Managed,
			apiserverConfig: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			},
		},
		{
			name:            "get apiserver config errors",
			targetNamespace: "openshift-apiserver",
			managementState: operatorv1.Managed,
			apiserverConfig: nil,
			syncError: apierrors.NewNotFound(
				schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"},
				"cluster",
			),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: tc.managementState,
					},
				},
				&operatorv1.StaticPodOperatorStatus{},
				//	OperatorStatus: operatorv1.OperatorStatus{
				//		// we need to set up proper conditions before the test starts because
				//		// the controller calls UpdateStatus which calls UpdateOperatorStatus method which is unsupported (fake client) and throws an exception
				//		Conditions: []operatorv1.OperatorCondition{
				//			{
				//				Type:   "EncryptionStateControllerDegraded",
				//				Status: "False",
				//			},
				//		},
				//	},
				//	NodeStatuses: []operatorv1.NodeStatus{ // TODO: is this needed?
				//		{NodeName: "node-1"},
				//	},
				//},
				nil,
				nil,
			)

			fakeKubeClient := fake.NewClientset(tc.initialObjects...)
			kubeInformers := v1helpers.NewKubeInformersForNamespaces(fakeKubeClient, "openshift-config-managed", tc.targetNamespace)
			fakeSecretClient := fakeKubeClient.CoreV1()
			fakePodsGetter := fakeKubeClient.CoreV1()

			fakeConfigClient := configv1clientfake.NewClientset()
			if tc.apiserverConfig != nil {
				fakeConfigClient = configv1clientfake.NewClientset(tc.apiserverConfig)
			}
			fakeApiServerClient := fakeConfigClient.ConfigV1().APIServers()
			fakeApiServerInformer := configv1informers.NewSharedInformerFactory(fakeConfigClient, time.Minute).Config().V1().APIServers()

			eventRecorder := events.NewInMemoryRecorder("test-kmsPluginController", clocktesting.NewFakePassiveClock(time.Now()))
			provider := newTestProvider(
				[]schema.GroupResource{
					{Group: "", Resource: "secrets"},
				},
			)
			deployer, err := encryptiondeployer.NewRevisionLabelPodDeployer(
				"revision", tc.targetNamespace, kubeInformers, fakePodsGetter,
				fakeSecretClient, encryptiondeployer.StaticPodNodeProvider{OperatorClient: fakeOperatorClient},
			)
			if err != nil {
				t.Fatalf("failed to get deployer: %s", err)
			}

			ctlr := NewKMSPluginController(
				"openshift-apiserver",
				tc.targetNamespace,
				provider,
				deployer,
				alwaysFulfilledPreconditions,
				fakePodTemplateBuilderFunc,
				fakeApiServerClient,
				fakeOperatorClient,
				fakeSecretClient,
				metav1.ListOptions{},
				fakeApiServerInformer,
				kubeInformers,
				fakePodsGetter,
				eventRecorder,
			)
			err = ctlr.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))
			gotError := err != nil
			if !cmp.Equal(err, tc.syncError) {
				if gotError {
					t.Fatalf("expected PluginController.Sync error %q to match %q, but didn't", err, tc.syncError)
				} else {
					t.Fatal("expected PluginController.Sync to return an error, got nil")
				}
			}
		})
	}
}

func TestKMSPluginControllerConfigMapManagement(t *testing.T) {
	targetNamespace := "openshift-apiserver"
	// kmsPluginNameHash := "123" // TODO
	constantFakePodManifest, _ := constantFakePodTemplateBuilderFunc("", "", "", "", "", "")
	testCases := []struct {
		name             string
		encryptionConfig configv1.APIServerEncryption
		initialObjects   []runtime.Object
		syncError        error
		expectedActions  []ktesting.Action
		podTemplateFunc  kmsPluginPodTemplateBuilderFunc
	}{
		{
			name:            "creates configmap for static pod when one does not already exist",
			podTemplateFunc: fakePodTemplateBuilderFunc,
			encryptionConfig: configv1.APIServerEncryption{
				Type: configv1.EncryptionTypeKMS,
				KMS: &configv1.KMSConfig{
					Type: configv1.AWSKMSProvider,
					AWS: &configv1.AWSKMSConfig{
						Region: "us-east-1",
						KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
			},
			expectedActions: []ktesting.Action{
				ktesting.ActionImpl{
					Verb: "get",
					Resource: schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
				},
				ktesting.ActionImpl{
					Verb: "get",
					Resource: schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
				},
				ktesting.ActionImpl{
					Verb: "create",
					Resource: schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
				},
			},
		},
		{
			name:            "does not create configmap for static pod when pod already exists and is up-to-date",
			podTemplateFunc: constantFakePodTemplateBuilderFunc,
			encryptionConfig: configv1.APIServerEncryption{
				Type: configv1.EncryptionTypeKMS,
				KMS: &configv1.KMSConfig{
					Type: configv1.AWSKMSProvider,
					AWS: &configv1.AWSKMSConfig{
						Region: "us-east-1",
						KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
			},
			expectedActions: []ktesting.Action{
				ktesting.ActionImpl{
					Verb: "get",
					Resource: schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
				},
			},
			initialObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kms-plugin-pod",
						Namespace: targetNamespace,
					},
					Data: map[string]string{ // TODO: it's better to feed the pod.yaml from the test body so we can use the test paramters as input.
						"pod.yaml": constantFakePodManifest,
					},
				},
			},
		},
		{
			name:            "updates config map for static pod when current pod manifest differs from desired",
			podTemplateFunc: fakePodTemplateBuilderFunc,
			encryptionConfig: configv1.APIServerEncryption{
				Type: configv1.EncryptionTypeKMS,
				KMS: &configv1.KMSConfig{
					Type: configv1.AWSKMSProvider,
					AWS: &configv1.AWSKMSConfig{
						Region: "us-east-1",
						KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
			},
			expectedActions: []ktesting.Action{
				ktesting.ActionImpl{
					Verb: "get",
					Resource: schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
				},
				ktesting.ActionImpl{
					Verb: "get",
					Resource: schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
				},
				ktesting.ActionImpl{
					Verb: "update",
					Resource: schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
				},
			},
			initialObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kms-plugin-pod",
						Namespace: targetNamespace,
					},
					Data: map[string]string{
						"pod.yaml": "stale-static-pod-manifest",
					},
				},
			},
		},
		{
			name:            "configmap creation errors",
			podTemplateFunc: fakePodTemplateBuilderFunc,
			encryptionConfig: configv1.APIServerEncryption{
				Type: configv1.EncryptionTypeKMS,
				KMS: &configv1.KMSConfig{
					Type: configv1.AWSKMSProvider,
					AWS: &configv1.AWSKMSConfig{
						Region: "us-east-1",
						KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
			},
			syncError: apierrors.NewServiceUnavailable("Oops, something went wrong."),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiserverConfig := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					Encryption: tc.encryptionConfig,
				},
			}

			fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{},
				nil,
				nil,
			)

			fakeKubeClient := fake.NewClientset(tc.initialObjects...)
			fakeKubeClient.PrependReactor("create", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
				if tc.syncError != nil {
					return true, nil, tc.syncError
				}
				cm := action.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap)
				return true, cm, nil
			})

			kubeInformers := v1helpers.NewKubeInformersForNamespaces(fakeKubeClient, "openshift-config-managed", targetNamespace)
			fakeSecretClient := fakeKubeClient.CoreV1()
			fakePodsGetter := fakeKubeClient.CoreV1()
			fakeConfigmapsGetter := fakeKubeClient.CoreV1()

			fakeConfigClient := configv1clientfake.NewClientset(apiserverConfig)
			fakeApiServerClient := fakeConfigClient.ConfigV1().APIServers()
			fakeApiServerInformer := configv1informers.NewSharedInformerFactory(fakeConfigClient, time.Minute).Config().V1().APIServers()

			eventRecorder := events.NewInMemoryRecorder("test-kmsPluginController", clocktesting.NewFakePassiveClock(time.Now()))
			provider := newTestProvider(
				[]schema.GroupResource{
					{Group: "", Resource: "secrets"},
				},
			)
			deployer, err := encryptiondeployer.NewRevisionLabelPodDeployer(
				"revision", targetNamespace, kubeInformers, fakePodsGetter,
				fakeSecretClient, encryptiondeployer.StaticPodNodeProvider{OperatorClient: fakeOperatorClient},
			)
			if err != nil {
				t.Fatalf("failed to get deployer: %s", err)
			}

			ctlr := NewKMSPluginController(
				"openshift-apiserver",
				targetNamespace,
				provider,
				deployer,
				alwaysFulfilledPreconditions,
				tc.podTemplateFunc,
				fakeApiServerClient,
				fakeOperatorClient,
				fakeSecretClient,
				metav1.ListOptions{},
				fakeApiServerInformer,
				kubeInformers,
				fakeConfigmapsGetter,
				eventRecorder,
			)
			err = ctlr.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))
			gotError := err != nil
			if !cmp.Equal(err, tc.syncError) {
				if gotError {
					t.Errorf("expected PluginController.Sync error %q to match %q, but didn't", err, tc.syncError)
				} else {
					t.Error("expected PluginController.Sync to return an error, got nil")
				}
			}

			if tc.expectedActions != nil {
				gotActions := fakeKubeClient.Actions()
				if len(tc.expectedActions) != len(gotActions) {
					t.Logf("fakeKubeClient.Actions(): %+v", gotActions)
					t.Fatalf("length of expected actions does not match length of fakeKubeClient.Actions(), expected %d but got %d",
						len(tc.expectedActions), len(gotActions))
				}
				for i, action := range gotActions {
					expectedAction := tc.expectedActions[i]
					if action.GetResource() == expectedAction.GetResource() && action.GetVerb() == expectedAction.GetVerb() {
						continue
					}
					t.Errorf("expected action %s:%s missing from fakeKubeClient actions",
						expectedAction.GetVerb(), expectedAction.GetResource())
				}
			}
			fakeKubeClient.ClearActions()
			// _, status, _, _ := fakeOperatorClient.GetStaticPodOperatorState()
			// degradedCondition := v1helpers.FindOperatorCondition(status.Conditions, kmsPluginControllerDegradedCondition)
			// if gotError && degradedCondition.Status != operatorv1.ConditionTrue {
			// 	t.Logf("operator conditions: %v\n", status.Conditions)
			// 	t.Fatalf("expected %q condition to be True, got %q", kmsPluginControllerDegradedCondition, degradedCondition.Status)
			// }
		})
	}
}
