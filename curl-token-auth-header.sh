#! /bin/bash

scope=openid
state=FOO
client_id=kafka-server
client_secret=kafka-server-secret

b64creds=$(echo -n "$client_id:$client_secret" | base64 -i -)

# for possible response types,  see
#  https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660 
response_type=code
 
curl --insecure -s http://127.0.0.1:8080/token \
  -H "Authorization: Basic $b64creds" \
  -d scope=${scope} \
  -d state=${state} \
  -d grant_type=client_credentials \
  -d response_type=${response_type}
