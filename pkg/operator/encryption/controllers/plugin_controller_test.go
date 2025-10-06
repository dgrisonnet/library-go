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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/google/go-cmp/cmp"
)

func TestPluginController(t *testing.T) {
	testCases := []struct {
		name            string
		targetNamespace string
		managementState operatorv1.ManagementState
		apiserverConfig *configv1.APIServer
		initialObjects  []runtime.Object
		expectedError   error
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
			expectedError: apierrors.NewNotFound(
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
			fakePodClient := fakeKubeClient.CoreV1()

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
				"revision", tc.targetNamespace, kubeInformers, fakePodClient,
				fakeSecretClient, encryptiondeployer.StaticPodNodeProvider{OperatorClient: fakeOperatorClient},
			)
			if err != nil {
				t.Fatalf("failed to get deployer: %s", err)
			}

			ctlr := NewPluginController(
				"openshift-apiserver",
				tc.targetNamespace,
				provider,
				deployer,
				alwaysFulfilledPreconditions,
				fakeApiServerClient,
				fakeOperatorClient,
				fakeSecretClient,
				metav1.ListOptions{},
				fakeApiServerInformer,
				kubeInformers,
				fakePodClient.Pods(tc.targetNamespace),
				eventRecorder,
			)
			err = ctlr.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))
			gotError := err != nil
			if !cmp.Equal(err, tc.expectedError) {
				if gotError {
					t.Fatalf("expected PluginController.Sync error %q to match %q, but didn't", err, tc.expectedError)
				} else {
					t.Fatal("Expected PluginController.Sync to return an error, got nil")
				}
			}
		})
	}
}

func TestPluginControllerPodManagement(t *testing.T) {
	testCases := []struct {
		name            string
		targetNamespace string
		managementState operatorv1.ManagementState
		apiserverConfig *configv1.APIServer
		initialObjects  []runtime.Object
		expectedError   error
	}{
		{
			name:            "creates installer pod when kms static pod doesn't exist",
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
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var triggerStatusErrorFn func(string, *operatorv1.StaticPodOperatorStatus) error
			if tc.expectedError != nil {
				triggerStatusErrorFn = func(rv string, spec *operatorv1.StaticPodOperatorStatus) error {
					fmt.Printf("triggerStatusErrorFn rv: %s -- spec %+v \n", rv, *spec)
					return tc.expectedError
				}
			}

			fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: tc.managementState,
					},
				},
				&operatorv1.StaticPodOperatorStatus{},
				triggerStatusErrorFn,
				nil,
			)

			fakeKubeClient := fake.NewClientset(tc.initialObjects...)
			kubeInformers := v1helpers.NewKubeInformersForNamespaces(fakeKubeClient, "openshift-config-managed", tc.targetNamespace)
			fakeSecretClient := fakeKubeClient.CoreV1()
			fakePodClient := fakeKubeClient.CoreV1()

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
				"revision", tc.targetNamespace, kubeInformers, fakePodClient,
				fakeSecretClient, encryptiondeployer.StaticPodNodeProvider{OperatorClient: fakeOperatorClient},
			)
			if err != nil {
				t.Fatalf("failed to get deployer: %s", err)
			}

			ctlr := NewPluginController(
				"openshift-apiserver",
				tc.targetNamespace,
				provider,
				deployer,
				alwaysFulfilledPreconditions,
				fakeApiServerClient,
				fakeOperatorClient,
				fakeSecretClient,
				metav1.ListOptions{},
				fakeApiServerInformer,
				kubeInformers,
				fakeKubeClient.CoreV1().Pods(tc.targetNamespace),
				eventRecorder,
			)
			err = ctlr.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))
			if err != nil {
				t.Fatalf("unexpected sync error: %s", err)
			}

			// _, status, _, _ := fakeOperatorClient.GetStaticPodOperatorState()
			// degradedCondition := v1helpers.FindOperatorCondition(status.Conditions, kmsPluginControllerDegradedCondition)
			// if gotError && degradedCondition.Status != operatorv1.ConditionTrue {
			// 	t.Logf("operator conditions: %v\n", status.Conditions)
			// 	t.Fatalf("expected %q condition to be True, got %q", kmsPluginControllerDegradedCondition, degradedCondition.Status)
			// }
		})
	}
}
