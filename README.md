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
Example client with `curl` - using the include example script to run *curl* to test, and `jq` to format the response:
```
$ ./curl-token-auth-header.sh | jq
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJrYWZrYSIsImNsaWVudF9pZCI6ImthZmthLXNlcnZlciIsImV4cCI6MTc1ODA2NTcwMCwiaWF0IjoxNzU4MDY1NjQwLCJpc3MiOiJvaWRjLW1vY2stc2VydmVyIiwic2NvcGUiOiJvcGVuaWQiLCJzdWIiOiJrYWZrYS1zZXJ2ZXIifQ.qsYCL-4Z4M5PrxsbHhmtGHydtkMBdfuHDKXP4hZUUgNHE_BCZhG_MyaVgPWO60w7q0vd28plTMjvfCAc_gFaXXUFg713Z2Qo29DTYibWEO9TcnKc48wyt-ji9T6AbAdGwWe_K4AwTw8zDhy_RNzf0HK__AC6ld9TsuM0QLZ2h3ljExzY8jn1gA9g0iMdSPnpTYzqjL3G9P5H9rr1Dbj0wOOmn1XxKaCtBbkl9ArtmIJQ5DBZaUoTz0izHVvd1jd17Ho6Hc5FHBJE3mBQ9iYFDn15BZVv6jvtKMJH6mRIpDV9wg4M7UK8yQ7OlMW1fPA0MQefIvijEO-MU2TcaD8brw",
  "token_type": "Bearer",
  "expires_in": 60,
  "scope": "openid"
}
``` 
