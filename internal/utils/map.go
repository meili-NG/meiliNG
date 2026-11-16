package utils

import (
	"fmt"
	"reflect"
	"strings"
)

func Map[T, U any](arr []T, function func(T) U) []U {
	if arr == nil {
		return nil
	}

	var result = make([]U, 0)
	for _, v := range arr {
		result = append(result, function(v))
	}

	return result
}

func TransferUpdates[T, U any](dataSource T, target *U) {
	if target == nil {
		return
	}

	targetType := reflect.TypeOf(*target)
	targetValue := reflect.ValueOf(target).Elem()

	if targetType.Kind() == reflect.Ptr {
		if targetValue.IsNil() {
			return
		}

		targetType = targetType.Elem()
		targetValue = targetValue.Elem()
	}

	sourceType := reflect.TypeOf(dataSource)
	sourceValue := reflect.ValueOf(dataSource)

	if sourceType.Kind() == reflect.Ptr {
		if sourceValue.IsNil() {
			return
		}

		sourceType = sourceType.Elem()
		sourceValue = sourceValue.Elem()
	}

	if sourceType.Kind() == reflect.Struct && targetType.Kind() == reflect.Struct {
		for i := 0; i < sourceType.NumField(); i++ {
			sourceField := sourceType.Field(i)
			sourceFieldValue := sourceValue.Field(i)

			name := sourceField.Name
			_, found := targetType.FieldByName(name)
			if found {
				targetValue.FieldByName(name).Set(sourceFieldValue)
			}
		}
	}
}

// TransferData is used to transfer data from one struct to another struct.
// If the struct has same field name, the `origin` field data will be copied to return value
// If the destination struct doesn't have the field, it will be ignored.
func TransferData[T, U any](origin T) U {
	originType := reflect.TypeOf(origin)
	originValue := reflect.ValueOf(origin)

	var u U
	resultType := reflect.TypeOf(u)
	resultValue := reflect.ValueOf(&u).Elem()

	if originType.Kind() == reflect.Ptr {
		if originValue.IsNil() {
			return u
		}

		originType = originType.Elem()
		originValue = originValue.Elem()
	}

	if originType.Kind() == reflect.Struct && resultType.Kind() == reflect.Struct {
		transferStructFields(originType, originValue, resultType, resultValue)
	}

	return u
}

func transferStructFields(originType reflect.Type, originValue reflect.Value, resultType reflect.Type, resultValue reflect.Value) {
	for i := 0; i < originType.NumField(); i++ {
		originField := originType.Field(i)
		originFieldValue := originValue.Field(i)

		if originField.Anonymous {
			embeddedType := originField.Type
			embeddedValue := originFieldValue

			if embeddedType.Kind() == reflect.Ptr {
				if embeddedValue.IsNil() {
					continue
				}
				embeddedType = embeddedType.Elem()
				embeddedValue = embeddedValue.Elem()
			}

			if embeddedType.Kind() == reflect.Struct {
				transferStructFields(embeddedType, embeddedValue, resultType, resultValue)
				continue
			}
		}

		name := originField.Name
		_, found := resultType.FieldByName(name)

		if found {
			valueRes := resultValue.FieldByName(name)

			if valueRes.CanSet() {
				MoveTo(valueRes, originFieldValue)
			}
		}
	}
}

func MoveTo(target reflect.Value, origin reflect.Value) {
	if target.Type() == origin.Type() {
		target.Set(origin)
		return
	} else if target.Type().Kind() == reflect.Ptr {
		// target is pointer, check if origin is ptr or not
		if origin.Type().Kind() == reflect.Ptr {
			if !origin.IsNil() {
				target.Set(origin)
				return
			}
		} else if target.Type().Elem() == origin.Type() {
			target.Set(origin.Addr())
			return
		} else if origin.Type().Elem() == target.Type() {
			target.Set(origin.Elem())
			return
		}
	}

	if target.Type().Kind() == reflect.String {
		originType := origin.Type()

		// check if origin has string representation
		if originType.Kind() == reflect.String {
			target.SetString(origin.Interface().(string))
			return
		} else if originType.Kind() == reflect.Int {
			target.SetString(fmt.Sprintf("%d", origin.Int()))
			return
		} else if originType.Kind() == reflect.Float64 {
			target.SetString(fmt.Sprintf("%f", origin.Float()))
			return
		} else if originType.Kind() == reflect.Bool {
			target.SetString(fmt.Sprintf("%t", origin.Bool()))
			return
		} else if originType.Kind() == reflect.Ptr {
			if !origin.IsNil() {
				MoveTo(target, origin.Elem())
				return
			}

			return
		} else {
			if origin.CanInterface() {
				if stringer, ok := origin.Interface().(fmt.Stringer); ok {
					target.SetString(stringer.String())
					return
				}
			}

			// check if origin has string method
			if method := origin.MethodByName("String"); method.IsValid() {
				target.SetString(method.Call([]reflect.Value{})[0].String())
				return
			}
		}
	}

	panic("Cannot move data from " + origin.Type().String() + " to " + target.Type().String())
}

// TransferJSONData is used to transfer data from one struct to another struct,
// but it uses json tag as the reference.
//
// If the struct has same json tag, the `origin` field data will be copied to return value
// If the destination struct doesn't have the field, it will be ignored.
func TransferJSONData[T, U any](origin T) U {
	originType, originValue := GetReflectionOfStruct(origin)

	var u U
	resultType, resultValue := GetModifiableReflectionOfStruct(&u)

	if originType.Kind() == reflect.Struct && resultType.Kind() == reflect.Struct {
		transferJSONFields(originType, originValue, resultType, resultValue)
	}

	return u
}

func transferJSONFields(originType reflect.Type, originValue reflect.Value, resultType reflect.Type, resultValue reflect.Value) {
	for i := 0; i < originType.NumField(); i++ {
		originField := originType.Field(i)
		originFieldValue := originValue.Field(i)

		// Flatten embedded (anonymous) struct fields
		if originField.Anonymous {
			embeddedType := originField.Type
			embeddedValue := originFieldValue
			if embeddedType.Kind() == reflect.Ptr {
				if embeddedValue.IsNil() {
					continue
				}
				embeddedType = embeddedType.Elem()
				embeddedValue = embeddedValue.Elem()
			}
			if embeddedType.Kind() == reflect.Struct {
				transferJSONFields(embeddedType, embeddedValue, resultType, resultValue)
				continue
			}
		}

		if originField.Tag.Get("json") == "-" {
			continue
		}

		name := strings.Split(originField.Tag.Get("json"), ",")[0]
		if name == "" {
			name = originField.Name
		}

		// find the field with same json tag
		for j := 0; j < resultType.NumField(); j++ {
			resultField := resultType.Field(j)
			resTag := resultField.Tag.Get("json")

			if resTag == "-" {
				continue
			}

			resName := strings.Split(resTag, ",")[0]
			if resName == "" {
				resName = resultField.Name
			}

			if name == resName {
				if valueField := resultValue.Field(j); valueField.CanSet() {
					MoveTo(valueField, originFieldValue)
				}
			}
		}
	}
}

func GetReflectionOfStruct[T any](src T) (reflectedType reflect.Type, reflectedValue reflect.Value) {
	reflectedType = reflect.TypeOf(src)
	reflectedValue = reflect.ValueOf(src)

	if reflectedType.Kind() == reflect.Ptr {
		if reflectedValue.IsNil() {
			return
		}

		reflectedType = reflectedType.Elem()
		reflectedValue = reflectedValue.Elem()
	}

	return reflectedType, reflectedValue
}

func GetModifiableReflectionOfStruct[T any](src *T) (reflectedType reflect.Type, reflectedValue reflect.Value) {
	reflectedType = reflect.TypeOf(*src)
	reflectedValue = reflect.ValueOf(src).Elem()

	if reflectedType.Kind() == reflect.Ptr {
		if reflectedValue.IsNil() {
			return
		}

		reflectedType = reflectedType.Elem()
		reflectedValue = reflectedValue.Elem()
	}

	return reflectedType, reflectedValue
}

func SerializeToMap[T any](src T) map[string]any {
	result := make(map[string]any)

	srcType, srcValue := GetReflectionOfStruct(src)

	if srcType.Kind() == reflect.Struct {
		for i := 0; i < srcType.NumField(); i++ {
			field := srcType.Field(i)
			value := srcValue.Field(i).Interface()

			tag := field.Tag.Get("json")
			if tag == "-" {
				continue
			}

			name := strings.Split(tag, ",")[0]
			if name == "" {
				name = field.Name
			}

			if reflect.TypeOf(value).Kind() == reflect.Struct {
				value = SerializeToMap(value)
			}

			result[name] = value
		}
	}

	return result
}

func ParseDeserialized[T any](target map[string]any, parseResult *T) {
	resultType := reflect.TypeOf(parseResult).Elem()
	reflected := reflect.ValueOf(parseResult).Elem()

	if resultType.Kind() == reflect.Struct {
		// get each element of the struct
		for i := 0; i < resultType.NumField(); i++ {
			field := resultType.Field(i)

			// get tag
			tag := field.Tag.Get("json")

			if tag == "-" {
				continue
			}

			// get name
			name := strings.Split(tag, ",")[0]
			if name == "" {
				name = field.Name
			}

			value := target[name]

			if targetField := reflected.Field(i); targetField.CanSet() {
				// update parseResult with value
				if field.Type.Kind() == reflect.String {
					reflected.Field(i).SetString(value.(string))
				} else {
					reflected.Field(i).Set(reflect.ValueOf(value))
				}
			}
		}
	}
}

func CompareArgs[T, U any](source T, target U, args ...string) bool {
	return ComparePreprocessedArgs(source, target, nil, args...)
}

func ComparePreprocessedArgs[T, U any](source T, target U, preprocessor func(a any) any, args ...string) bool {
	srcType, srcValue := GetReflectionOfStruct(source)
	tgtType, tgtValue := GetReflectionOfStruct(target)

	if srcType.Kind() == reflect.Struct && tgtType.Kind() == reflect.Struct {
		for _, arg := range args {
			field := tgtValue.FieldByName(arg)
			if field.IsValid() {
				srcField := srcValue.FieldByName(arg)
				if srcField.IsValid() {
					// check if the field value is the same
					srcFieldValue := srcField.Interface()
					tgtFieldValue := field.Interface()

					if preprocessor != nil {
						srcFieldValue = preprocessor(srcFieldValue)
						tgtFieldValue = preprocessor(tgtFieldValue)
					}

					if srcFieldValue != tgtFieldValue {
						return false
					}
				} else {
					return false
				}
			} else {
				return false
			}
		}
	}

	return true
}
