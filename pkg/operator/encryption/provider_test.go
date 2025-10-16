package encryption

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestNewEncryptionProvider(t *testing.T) {
	testCases := []struct {
		name                            string
		expectedProviderName            string
		expectedEncryptedGroupResources []schema.GroupResource
		encryptionConfig                configv1.APIServerEncryption
	}{
		{
			name:                 "with AESCBC encryption",
			expectedProviderName: "static",
			expectedEncryptedGroupResources: []schema.GroupResource{
				{Group: "", Resource: "secrets"},
				{Group: "", Resource: "configmaps"},
			},
			encryptionConfig: configv1.APIServerEncryption{
				Type: configv1.EncryptionTypeAESCBC,
			},
		},
		{
			name:                 "with KMS encryption",
			expectedProviderName: "kms",
			expectedEncryptedGroupResources: []schema.GroupResource{
				{Group: "", Resource: "secrets"},
				{Group: "", Resource: "configmaps"},
			},
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
		},
		{
			name:                 "with empty encryption config",
			expectedProviderName: "static",
			expectedEncryptedGroupResources: []schema.GroupResource{
				{Group: "", Resource: "secrets"},
				{Group: "", Resource: "configmaps"},
			},
			encryptionConfig: configv1.APIServerEncryption{},
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
			fakeConfigClient := configv1clientfake.NewClientset(apiserverConfig)

			p := NewEncryptionProvider(
				tc.expectedEncryptedGroupResources, fakeConfigClient.ConfigV1().APIServers(),
			)
			if p == nil {
				t.Fatal("NewEncryptionProvider unexpectedly returned nil")
			}
			providerName := p.Name()
			expectedName := tc.expectedProviderName
			if expectedName != providerName {
				t.Fatalf(
					"expected provider name to be %q, but got %q",
					expectedName, providerName,
				)
			}
			providerGRs := p.EncryptedGRs()
			expectedGRs := tc.expectedEncryptedGroupResources
			if !cmp.Equal(expectedGRs, providerGRs) {
				t.Log(cmp.Diff(expectedGRs, providerGRs))
				t.Fatal("expected group resources did not match provider group resources")
			}
		})
	}
}
