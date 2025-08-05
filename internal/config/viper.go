package config

// ViperInterface allows us to mock out viper
// during testing.
type ViperInterface interface {
	GetString(key string) string
	GetBool(key string) bool
	GetStringSlice(key string) []string
}
