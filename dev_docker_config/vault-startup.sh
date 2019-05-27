#!/bin/sh

/var/vault/vault-post-startup.sh &

exec vault server -dev -config /var/vault/config.hcl
