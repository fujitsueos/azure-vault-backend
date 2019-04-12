package main

import (
	"context"
	"reflect"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathAccessToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "token",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathAccessTokenRead,
		},
	}
}

func (b *backend) pathAccessTokenRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	AADEndpoint := azure.PublicCloud.ActiveDirectoryEndpoint
	config, err := b.getConfig(ctx, req.Storage)
	var resource string
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(azureConfig)
	}

	if !IsEmptyEnvironment(config.EnvStruct) {
		resource = config.EnvStruct.ResourceManagerEndpoint
	} else {
		resource = azure.PublicCloud.ResourceManagerEndpoint
	}

	oauthConfig, err := adal.NewOAuthConfig(AADEndpoint, config.TenantID)
	if err != nil {
		return nil, err
	}

	spt, err := adal.NewServicePrincipalToken(*oauthConfig, config.ClientID, config.ClientSecret, resource)
	if err != nil {
		return nil, err
	}

	if err = spt.Refresh(); err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"access_token": spt.Token().AccessToken,
		},
	}
	return resp, nil
}

func IsEmptyEnvironment(e azure.Environment) bool {
	return reflect.DeepEqual(e, azure.Environment{})
}
