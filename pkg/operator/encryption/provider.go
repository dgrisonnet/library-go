package encryption

import (
	"context"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func NewEncryptionProvider(
	grs []schema.GroupResource,
	apiserverClient configv1client.APIServerInterface,
) controllers.Provider {
	rp := make(StaticEncryptionResourceProvider, 0, len(grs))
	for _, gr := range grs {
		rp = append(rp, gr)
	}

	var provider controllers.Provider = StaticEncryptionProvider{
		resourceProvider: rp,
	}

	apiserver, err := apiserverClient.Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		// TODO: log this error
		return provider
	}
	switch apiserver.Spec.Encryption.Type {
	case configv1.EncryptionTypeKMS:
		provider = KMSEncryptionProvider{
			resourceProvider: rp,
		}
	default:
		return provider // will be the static provider
	}
	return provider
}
