package cache

import (
	"context"
)

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)

	Put(ctx context.Context, key string, data []byte) error
}
