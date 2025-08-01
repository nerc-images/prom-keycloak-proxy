# prom-keycloak-proxy
A proxy for observatorium and prometheus on OpenShift,
secured by Keycloak Fine-Grained Resource Permissions.

## How to run the application as a Podman container

### Install the prerequiste packages for buildah and podman

```bash
pkcon install -y buildah
pkcon install -y podman
```

### Build the container with podman

```bash
cd prom-keycloak-proxy/
podman build -t nerc-images/prom-keycloak-proxy:latest .
```

### Push the container up to quay.io

```bash
podman login quay.io
podman push nerc-images/prom-keycloak-proxy:latest quay.io/nerc-images/prom-keycloak-proxy:latest
```

### Run the container image to test

Obtain the Keycloak admin password in the `keycloak-initial-admin` Secret.

```bash
PROXY_AUTH_BASE_URL=https://keycloak.apps-crc.testing
PROXY_ACM_HUB=moc
PROXY_AUTH_REALM=NERC
PROXY_AUTH_CLIENT_ID=ai-telemetry
PROXY_AUTH_CLIENT_SECRET=Find the client secret to query for authorization permissions by using the Keycloak admin
```

Obtain the prometheus TLS certificate, TLS key, and CA certificate from OpenShift.

```bash
oc -n open-cluster-management-observability extract secret/observability-grafana-certs --keys=tls.crt --to=$HOME/Downloads/
oc -n open-cluster-management-observability extract secret/observability-grafana-certs --keys=tls.key --to=$HOME/Downloads/
oc -n open-cluster-management-observability extract secret/observability-server-ca-certs --keys=ca.crt --to=$HOME/Downloads/
```

Run the prom-keycloak-proxy container by configuring the right connection information to both Keycloak and Prometheus.

```bash
podman run --rm -p 8080:8080 \
  -e PROXY_AUTH_CLIENT_ID=$PROXY_AUTH_CLIENT_ID \
  -e PROXY_AUTH_CLIENT_SECRET=$PROXY_AUTH_CLIENT_SECRET \
  -e PROXY_ACM_HUB=$PROXY_ACM_HUB \
  -e PROXY_AUTH_REALM=$PROXY_AUTH_REALM \
  -e PROXY_AUTH_BASE_URL=$PROXY_AUTH_BASE_URL \
  -e PROXY_AUTH_TLS_VERIFY=false \
  -e PROXY_PROMETHEUS_BASE_URL=https://observatorium-api-open-cluster-management-observability.apps.example.com/api/metrics/v1/default \
  -e PROXY_PROMETHEUS_CA_CRT=/opt/Downloads/ca.crt \
  -e PROXY_PROMETHEUS_TLS_CRT=/opt/Downloads/tls.crt \
  -e PROXY_PROMETHEUS_TLS_KEY=/opt/Downloads/tls.key \
  -v /home/ctate/Downloads:/opt/Downloads \
  --privileged \
  nerc-images/prom-keycloak-proxy:latest
```

Acting on behalf of a user application, obtain the client ID and client secret for the user application.

```bash
PROXY_AUTH_CLIENT_ID=ai4cloudops
PROXY_AUTH_CLIENT_SECRET=Find the client secret for your PROXY_AUTH_CLIENT_ID above
```

Obtain an auth token for the user application

```bash
AUTH_TOKEN=$(curl -X POST -k -s -u "$PROXY_AUTH_CLIENT_ID:$PROXY_AUTH_CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  "$PROXY_AUTH_BASE_URL/realms/$PROXY_AUTH_REALM/protocol/openid-connect/token" \
  | jq -r ".access_token")
echo $AUTH_TOKEN
echo DONE
```

Query the prom-keycloak-proxy with the user token, 
and prom-keycloak-proxy will query Keycloak authorization permissions on behalf of the user.

```bash
curl -i 'http://localhost:8080/api/v1/query' --get \
  --data-urlencode 'query=cluster:cpu_cores:sum{cluster="nerc-ocp-prod"}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

If the user application is authorized to access the given cluster metrics, you will see a successful response.

```bash
HTTP/1.1 200 OK
Vary: Origin
Date: Wed, 08 May 2024 16:44:35 GMT
Content-Length: 196
Content-Type: text/plain; charset=utf-8

{"data":{"result":[{"metric":{"__name__":"cluster:cpu_cores:sum","cluster":"nerc-ocp-prod","usage":"grafana-dashboard"},"value":[...]}],"resultType":"vector"},"status":"success"}
```

If the user application is not authorized to access another cluster's metrics like `nerc-ocp-infra`,

```bash
curl -i 'http://localhost:8080/api/v1/query' --get \
  --data-urlencode 'query=cluster:cpu_cores:sum{cluster="nerc-ocp-infra"}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

you will see a failed response. 

```bash
HTTP/1.1 403 Forbidden
Vary: Origin
Date: Wed, 08 May 2024 16:47:24 GMT
Content-Length: 95
Content-Type: text/plain; charset=utf-8

{"code":401,"error":"Unauthorized","message":"You are not authorized to access this resource"}
```

You can use the [Test API Jupyter Notebook](doc/test-api.ipynb) to help you test your prom-keycloak-proxy API.
