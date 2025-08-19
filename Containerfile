FROM docker.io/golang:1.22

ENV PROXY_AUTH_CLIENT_ID="" \
  PROXY_AUTH_CLIENT_SECRET="" \
  PROXY_ACM_HUB="" \
  PROXY_AUTH_REALM="" \
  PROXY_AUTH_BASE_URL="" \
  PROXY_AUTH_TLS_VERIFY="true" \
  PROXY_PROMETHEUS_BASE_URL="" \
  PROXY_PROMETHEUS_CA_CRT="/opt/proxy-prometheus-ca.crt" \
  PROXY_PROMETHEUS_TLS_CRT="/opt/proxy-prometheus-tls.crt" \
  PROXY_PROMETHEUS_TLS_KEY="/opt/proxy-prometheus-tls.key"

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY domains/ domains/
COPY errors/ errors/
COPY internal/ internal/
COPY queries/ queries/
COPY services/ services/
RUN CGO_ENABLED=0 GOOS=linux go build -o /prom-keycloak-proxy
CMD ["/prom-keycloak-proxy"]
