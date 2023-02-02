package vpplink

func DefaultIntTo(value, defaultValue int) int {
	if value == 0 {
		return defaultValue
	} else {
		return value
	}
}
