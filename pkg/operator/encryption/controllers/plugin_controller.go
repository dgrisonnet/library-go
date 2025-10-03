package controllers

import (
	"context"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

type pluginController struct {
	instanceName           string
	targetNamespace        string
	controllerInstanceName string

	operatorClient  operatorv1helpers.OperatorClient
	secretClient    corev1client.SecretsGetter
	apiServerClient configv1client.APIServerInterface

	deployer                 statemachine.Deployer
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled

	kmsConfig configv1.KMSConfig
}

func NewPluginController(
	instanceName string,
	targetNamespace string,
	provider Provider,
	deployer statemachine.Deployer,
	preconditionsFulfilledFn preconditionsFulfilled,
	apiServerClient configv1client.APIServerInterface,
	operatorClient operatorv1helpers.OperatorClient,
	secretClient corev1client.SecretsGetter,
	encryptionSecretSelector metav1.ListOptions,
	apiServerInformer configv1informers.APIServerInformer,
	eventRecorder events.Recorder,
) factory.Controller {
	c := pluginController{
		instanceName:           instanceName,
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "KMSPlugin"),
		targetNamespace:        targetNamespace,
		operatorClient:         operatorClient,
		apiServerClient:        apiServerClient,
		provider:               provider,

		preconditionsFulfilledFn: preconditionsFulfilledFn,
	}

	return factory.New().
		WithSync(c.sync).
		WithControllerInstanceName(c.controllerInstanceName).
		ResyncEvery(time.Minute).
		WithInformers(
			apiServerInformer.Informer(),
			operatorClient.Informer(),
			deployer,
		).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("kms-plugin-controller"),
	)
}

func (c *pluginController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	// The status for this condition is intentionally omitted to ensure it's correctly set in each branch
	degradedCondition := applyoperatorv1.OperatorCondition().
		WithType("EncryptionKMSPluginControllerDegraded")

	defer func() {
		if degradedCondition == nil {
			return
		}
		status := applyoperatorv1.OperatorStatus().WithConditions(degradedCondition)
		if applyError := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); applyError != nil {
			err = applyError
		}
	}()

	if ready, err := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); err != nil || !ready {
		if err != nil {
			degradedCondition = nil
		} else {
			degradedCondition = degradedCondition.
				WithStatus(operatorv1.ConditionFalse)
		}
		return err // we will get re-kicked when the operator status updates
	}

	apiServer, err := c.apiServerClient.Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return err
	}
	kmsConfig := apiServer.Spec.Encryption.KMS
	if kmsConfig == nil {
		return nil
	}

	switch c.kmsConfig.Type {
	case configv1.AWSKMSProvider:
		// create aws plugin
	default:
		// error
	}

	return nil
}
