package utils

import (
	"reflect"
	"slices"
	"strings"
)

func Sanitizer[T any](t T, flags ...string) T {
	reflectedType := reflect.TypeOf(t)
	reflectedValue := reflect.ValueOf(t)

	if reflectedType.Kind() == reflect.Ptr {
		if reflectedValue.IsNil() {
			return t
		}

		reflectedType = reflectedType.Elem()
		reflectedValue = reflectedValue.Elem()
	}

	var u T
	targetReflectValue := reflect.ValueOf(&u).Elem()

	if reflectedType.Kind() == reflect.Struct {
		for i := 0; i < reflectedType.NumField(); i++ {
			field := reflectedType.Field(i)
			value := reflectedValue.Field(i)
			targetField := targetReflectValue.Field(i)

			tag := field.Tag.Get("sanitizer")
			if tag == "" {
				// no tag, just copy the value
				MoveTo(targetField, value)
				continue
			} else if tag == "-" {
				// skip this field
				continue
			}

			options := strings.Split(tag, ",")
			if !targetField.CanSet() {
				// cannot set the field, skip
				continue
			}

			for _, flag := range flags {
				if flag == "-" || slices.Contains(options, flag) {
					MoveTo(targetField, value)
					break
				}
			}
		}
	}

	return u
}
