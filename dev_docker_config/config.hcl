listener "tcp" {
  tls_key_file = "/var/vault/certs/server.key"
  tls_cert_file = "/var/vault/certs/server.crt"
  tls_disable  = false
  address = "0.0.0.0:8443"
}
