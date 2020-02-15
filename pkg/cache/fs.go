package cache

import (
	"context"
	"math/rand"
	"os"
	"strconv"

	"github.com/spf13/afero"
)

type fsCache struct {
	fs afero.Fs
}

var _ Cache = (*fsCache)(nil)

func NewFsCache(fs afero.Fs) *fsCache {
	return &fsCache{
		fs: fs,
	}
}

func (fc *fsCache) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := afero.ReadFile(fc.fs, key)
	if os.IsNotExist(err) {
		err = ErrCacheMiss
	}
	return data, err
}

func (fc *fsCache) Put(ctx context.Context, key string, data []byte) (err error) {
	tmpName := "_cache" + strconv.Itoa(rand.Int())
	defer func() {
		fc.fs.Remove(tmpName)
	}()
	if err = afero.WriteFile(fc.fs, tmpName, data, 0600); err != nil {
		return
	}
	return fc.fs.Rename(tmpName, key)
}
