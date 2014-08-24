package util

import (
	"fmt"
	"github.com/peterbourgon/diskv"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

var appDir string = "~/.bitnet"

func GetAppData(filename string) (*os.File, error) {
	filename, err := normalizeFilename(filename)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	return file, nil
}

func StoreAppData(filename string, data []byte, perm os.FileMode) error {
	filename, err := normalizeFilename(filename)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	defer file.Close()
	if err != nil {
		return err
	}

	if err := file.Chmod(perm); err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		return err
	}

	return nil
}

func normalizeFilename(filename string) (string, error) {
	if path.IsAbs(filename) {
		if !strings.Contains(filename, AppDir()) {
			return "", fmt.Errorf("expected app dir %v in %v", AppDir(), filename)
		}
		return filename, nil
	}
	if path.Dir(filename) != "." {
		panic("TODO implement if needed")
	}
	filename = AppDir() + "/" + filename
	return filename, nil
}

func MakeAppDir() error {
	if err := makeDir(AppDir()); err != nil {
		return err
	}
	return nil
}

func AppDir() string {
	re := regexp.MustCompile("^~")
	dir := string(re.ReplaceAll([]byte(appDir), []byte(os.Getenv("HOME"))))
	return dir
}

func SetAppDir(newAppDir string) {
	appDir = newAppDir
}

func makeDir(dir string) error {
	if err := os.MkdirAll(dir, 0775); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func GetOrCreateDB(path string) *diskv.Diskv {
	flatTransform := func(s string) []string { return []string{} }
	d := diskv.New(diskv.Options{
		BasePath:     path,
		Transform:    flatTransform,
		CacheSizeMax: 1024 * 1024,
	})
	return d
}

func InitTempAppDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Init temp dir: %v\n", dir)
	SetAppDir(dir)
	return dir
}
