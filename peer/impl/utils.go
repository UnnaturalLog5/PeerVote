package impl

// contains checks whether elem of type T is contained in slice arr
func contains[T comparable](arr []T, elem T) bool {
	for _, s := range arr {
		if elem == s {
			return true
		}
	}
	return false
}
