package utils

func Repeat[T any](base T, count int) []T {
	ret := make([]T, count)

	for i := 0; i < count; i++ {
		ret[i] = base
	}

	return ret
}
