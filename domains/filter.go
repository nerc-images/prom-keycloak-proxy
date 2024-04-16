package domains

type Filter struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
}
