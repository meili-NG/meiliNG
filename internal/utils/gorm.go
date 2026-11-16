package utils

import (
	"reflect"
	"strings"
)

func SerializeGORMColumnsToMap[T any](data T, columnNames ...string) map[string]any {
	var result = map[string]any{}

	var dataType = reflect.TypeOf(data)
	var value = reflect.ValueOf(data)

	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return result
		}

		dataType = dataType.Elem()
		value = value.Elem()
	}

	for _, columnName := range columnNames {
		var field = value.FieldByName(columnName)
		typeField, ok := dataType.FieldByName(columnName)

		if !ok {
			continue
		}

		gormFieldName := ""
		if field.IsValid() {
			tag := typeField.Tag.Get("gorm")
			tagSplitted := strings.Split(tag, ";")

			for _, tagPart := range tagSplitted {
				if strings.HasPrefix(tagPart, "column:") {
					gormFieldName = strings.TrimPrefix(tagPart, "column:")
				}
			}

			if gormFieldName == "" {
				panic("gorm field name not found")
			}
		}

		if field.IsValid() {
			result[columnName] = field.Interface()
		}
	}

	return result
}
