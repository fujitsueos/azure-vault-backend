package main

import (
	"context"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
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
	var environment azure.Environment
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(azureConfig)
	}

	if config.Environment != "" {
		environment, _ = azure.EnvironmentFromName(config.Environment)
	} else {
		environment = azure.PublicCloud
	}

	oauthConfig, err := adal.NewOAuthConfig(AADEndpoint, config.TenantID)
	if err != nil {
		return nil, err
	}

	spt, err := adal.NewServicePrincipalToken(*oauthConfig, config.ClientID, config.ClientSecret, environment.ResourceManagerEndpoint)
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
