package encryption

import (
	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type KMSEncryptionProvider struct {
	encryptedGroupResources []schema.GroupResource
	resourceProvider        ResourceProvider
}

var _ controllers.Provider = StaticEncryptionProvider{}

func (p KMSEncryptionProvider) EncryptedGRs() []schema.GroupResource {
	return p.resourceProvider.EncryptedGRs()
}

func (p KMSEncryptionProvider) ShouldRunEncryptionControllers() (bool, error) {
	// TODO: calculate depending on KMS plugin status
	return true, nil
}

func (p KMSEncryptionProvider) Name() string {
	return "kms"
}
