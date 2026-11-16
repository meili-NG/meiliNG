package utils

import (
	"github.com/modern-go/reflect2"
)

// CopyFields copies matching fields from src to dst by field name using reflect2
func CopyFields(src, dst interface{}) {
	srcType := reflect2.TypeOf(src)
	dstType := reflect2.TypeOf(dst)

	srcStructType := srcType.(*reflect2.UnsafePtrType).Elem().(*reflect2.UnsafeStructType)
	dstStructType := dstType.(*reflect2.UnsafePtrType).Elem().(*reflect2.UnsafeStructType)

	for i := 0; i < dstStructType.NumField(); i++ {
		dstField := dstStructType.Field(i)
		srcField := srcStructType.FieldByName(dstField.Name())
		if srcField != nil {
			srcVal := srcField.Get(src)
			dstField.Set(dst, srcVal)
		}
	}
}
