package utils

func Contains[T comparable](haystack []T, needle T) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func Deduplicate[T comparable](haystack []T) []T {
	var result []T
	var store map[T]bool = make(map[T]bool)

	for _, item := range haystack {
		if _, ok := store[item]; !ok {
			store[item] = true
			result = append(result, item)
		}
	}
	return result
}

func Find[T any](haystack []T, predicate func(T) bool) (result T, found bool) {
	var t T
	for _, item := range haystack {
		if predicate(item) {
			return item, true
		}
	}

	return t, false
}

func Filter[T any](haystack []T, predicate func(T) bool) []T {
	var result []T
	for _, item := range haystack {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

func HasAll[T comparable](haystack []T, needles []T) bool {
	if len(haystack) < len(needles) {
		return false
	}

	haystackSet := make(map[T]bool, len(haystack))
	for _, item := range haystack {
		haystackSet[item] = true
	}

	for _, needle := range needles {
		if _, exists := haystackSet[needle]; !exists {
			return false
		}
	}

	return true
}
