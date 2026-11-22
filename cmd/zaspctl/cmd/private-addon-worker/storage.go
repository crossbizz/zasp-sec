package main

import "os"

// An exclusive preparation file serializes same-grant attempts. Data is
// flushed before publishing its final name by the platform's durable rename.
func persistFile(root *os.Root, temp, name string, data []byte) error {
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = publishName(root, temp, name)
	}
	if err != nil {
		_ = root.Remove(temp)
	}
	return err
}
