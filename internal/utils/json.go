package utils

func MergeJSON(a, b map[string]interface{}) map[string]interface{} {
	if a == nil && b != nil {
		a = make(map[string]interface{}, len(b))
	}

	if b == nil {
		if a != nil {
			return a
		} else {
			return nil
		}
	}

	for k, v := range b {
		if _, ok := a[k].(map[string]interface{}); ok {

			// check if v is a map
			if _, ok := v.(map[string]interface{}); ok {
				a[k] = MergeJSON(a[k].(map[string]interface{}), v.(map[string]interface{}))
				continue
			}
		}

		a[k] = v
	}
	return a
}
