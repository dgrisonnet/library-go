package encryption

import "k8s.io/apimachinery/pkg/runtime/schema"

type ResourceProvider interface {
	EncryptedGRs() []schema.GroupResource
}

type StaticEncryptionResourceProvider []schema.GroupResource

func (p StaticEncryptionResourceProvider) EncryptedGRs() []schema.GroupResource {
	return p
}
