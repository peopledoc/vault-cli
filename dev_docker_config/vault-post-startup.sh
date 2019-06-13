#!/bin/sh

sleep 3

export VAULT_ADDR=https://localhost:8443 VAULT_SKIP_VERIFY=1

vault login some-token

vault secrets enable -path=secretkvv1 -version=1 kv

vault policy write dev-policy /var/vault/policy.hcl

vault auth enable cert

vault write auth/cert/certs/cert-login certificate=@/var/vault/certs/client.crt policies=dev-policy name=cert-login

vault auth enable userpass

vault write auth/userpass/users/userpass-login password=userpass-pass policies=dev-policy
