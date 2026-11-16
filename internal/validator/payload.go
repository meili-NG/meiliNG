package validator

import (
	"reflect"
	"strings"

	"github.com/meili-NG/meiliNG/v2/internal/utils"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
)

// ValidatePayloadOrError validates a payload and returns an error if validation fails
func ValidatePayloadOrError[T any](payload T) error {
	if valid, missed := validatePayload(payload); !valid {
		missedParams := strings.Join(missed, ", ")
		return meilingErrors.NewMeilingError(meilingErrors.ErrInvalidRequest, "missing required parameters: "+missedParams)
	}

	return nil
}

func validatePayload[T any](payload T) (bool, []string) {
	target := reflect.TypeOf(payload)

	if target.Kind() == reflect.Ptr {
		target = target.Elem()
	}

	var missingFields []string
	if target.Kind() == reflect.Struct {
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)

			tags := field.Tag.Get("validate")
			if tags == "required" {
				valueType := field.Type
				valueField := reflect.ValueOf(payload).Field(i)
				value := valueField.Interface()

				if valueType.Kind() == reflect.Ptr {
					if value == nil {
						missingFields = append(missingFields, field.Name)
					} else {
						ptrDerefType := valueType.Elem()
						valueType = ptrDerefType
						value = valueField.Elem().Interface()
					}
				}

				if valueType.Kind() == reflect.String {
					if value == "" {
						missingFields = append(missingFields, field.Name)
					}
				} else if valueType.Kind() == reflect.Slice {
					if reflect.ValueOf(value).Len() == 0 {
						missingFields = append(missingFields, field.Name)
					}
				} else if valueType.Kind() == reflect.Struct {
					if valid, missed := validatePayload(value); !valid {
						currentMissed := utils.Map(missed, func(m string) string {
							return field.Name + "." + m
						})

						missingFields = append(missingFields, currentMissed...)
					}
				}
			}
		}
	}

	if len(missingFields) > 0 {
		return false, missingFields
	} else {
		return true, nil
	}
}
