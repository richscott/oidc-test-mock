# oidc-test-mock
A tiny OIDC server for testing OIDC clients. This server was written primarily for
testing OIDC clients connecting to an Apache Kafka server, but may be useful for
other testing applications.

There are basically two endpoints: the usual OIDC /token endpoint, and also the JWKS "well-known"
endpoint, which Kafka queries upon its startup (when Kafka is configured for OIDC auth).

## Building
```
$ go build
```

## Running
By default, the server serves plain HTTP over port 8080. Specify the `-tls` option to use
TLS and pass the server cert and private key files with the  `-cert` and `-key` file options.
The `-h` (help) option prints out all available options.

Client IDs and secrets are hard-wired in the code, for now. 

```
$ ./oidc-test-mock
2025/09/16 17:16:24 OIDC Mock Server starting on :8080
2025/09/16 17:16:24 Token endpoint: http://localhost:8080/token
2025/09/16 17:16:24 JWKS endpoint: http://localhost:8080/.well-known/jwks.json
2025/09/16 17:16:24 Valid clients: test_client/test_secret, demo_client/demo_secret, kafka-server/kafka-server-secret
````

Using TLS:
```
$ ./oidc-test-mock -tls -cert server.crt -key server.key
2025/09/16 17:22:07 OIDC Mock Server starting on :8080 with TLS
2025/09/16 17:22:07 Token endpoint: https://localhost:8080/token
2025/09/16 17:22:07 JWKS endpoint: https://localhost:8080/.well-known/jwks.json
2025/09/16 17:22:07 Valid clients: kafka-server/kafka-server-secret, test_client/test_secret, demo_client/demo_secret
2025/09/16 17:22:07 Using certificate: server.crt
2025/09/16 17:22:07 Using private key: server.key
```
