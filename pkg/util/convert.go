package util

import (
	"reflect"
	"unsafe"
)

func LocalStringToBytes(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: sh.Data,
		Len:  sh.Len,
		Cap:  sh.Len,
	}))
}

func LocalByteToString(buf []byte) string {
	return *(*string)(unsafe.Pointer(&buf))
}
