package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"

	"github.com/fumiama/simple-storage/helper"
)

// handle 无法防范中间人攻击，请在安全内网使用
func handle(route string, path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !s.IsDir() {
		return os.ErrInvalid
	}
	dir, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	filesinfo := make(map[string][16]byte, len(dir))
	var infolk sync.RWMutex
	var wg sync.WaitGroup

	n := runtime.NumCPU()
	i := 0
	p := len(dir) / n
	if p == 0 {
		p = 1
	}

	fmt.Println("perparing route", route, "with", len(dir), "files in path", path)
	if len(dir) > n {
		for ; i < len(dir)-p; i += p {
			fmt.Println("perparing", i, "to", i+p)
			wg.Add(1)
			go func(dir []fs.DirEntry) {
				for _, e := range dir {
					if !e.IsDir() {
						data, err := os.ReadFile(path + "/" + e.Name())
						if err != nil {
							continue
						}
						m := md5.Sum(data)
						infolk.Lock()
						filesinfo[e.Name()] = m
						infolk.Unlock()
					}
				}
				wg.Done()
			}(dir[i : i+p])
		}
	}
	fmt.Println("perparing", i, "to", len(dir))
	for _, e := range dir[i:] {
		if !e.IsDir() {
			data, err := os.ReadFile(path + "/" + e.Name())
			if err != nil {
				return err
			}
			m := md5.Sum(data)
			infolk.Lock()
			filesinfo[e.Name()] = m
			infolk.Unlock()
		}
	}
	wg.Wait()
	fmt.Printf("finish\n\n")

	http.HandleFunc(route, func(rw http.ResponseWriter, r *http.Request) {
		// 检查url
		q := r.URL.Query()
		arg := getfirst("arg", &q)
		switch arg {
		case "has":
			name := getfirst("name", &q)
			if name == "" {
				goto BADREQ
			}
			name, err = url.QueryUnescape(name)
			if err != nil {
				goto BADREQ
			}
			infolk.RLock()
			m, ok := filesinfo[name]
			infolk.RUnlock()
			retb := make([]byte, 17)
			if ok {
				retb[0] = 1
				copy(retb[1:], m[:])
			}
			rw.Write(retb)
			return
		case "lst":
			infolk.RLock()
			dat, err := json.Marshal(&filesinfo)
			infolk.RUnlock()
			if err != nil {
				http.Error(rw, "500 Internal Server Error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			rw.Write(dat)
			return
		case "get":
			name := getfirst("name", &q)
			if name == "" {
				goto BADREQ
			}
			name, err = url.QueryUnescape(name)
			if err != nil {
				goto BADREQ
			}
			infolk.RLock()
			m, ok := filesinfo[name]
			infolk.RUnlock()
			if !ok {
				http.Error(rw, "404 NOT FOUND", http.StatusNotFound)
				return
			}
			rw.Header().Add("md5", url.QueryEscape(helper.BytesToString(m[:])))
			http.ServeFile(rw, r, path+"/"+name)
			return
		case "set":
			if r.Method != "POST" {
				http.Error(rw, "405 Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			name := getfirst("name", &q)
			if name == "" {
				goto BADREQ
			}
			name, err = url.QueryUnescape(name)
			if err != nil {
				goto BADREQ
			}
			// key 是 body 的 md5
			key := getfirst("key", &q)
			if key == "" {
				goto BADREQ
			}
			data, err := hex.DecodeString(key)
			if err != nil || len(data) != 16 {
				goto BADREQ
			}
			var m0 [16]byte
			copy(m0[:], data)
			if r.ContentLength <= 0 {
				goto BADREQ
			}
			buf := make([]byte, r.ContentLength)
			_, err = io.ReadFull(r.Body, buf)
			if err != nil {
				goto BADREQ
			}
			buf = mytea.Decrypt(buf)
			m := md5.Sum(buf)
			if m != m0 {
				goto BADREQ
			}
			infolk.RLock()
			m1, ok := filesinfo[name]
			infolk.RUnlock()
			if ok && m1 == m {
				io.WriteString(rw, "exist")
				return
			}
			infolk.Lock()
			filesinfo[name] = m
			err = os.WriteFile(path+"/"+name, buf, 0644)
			infolk.Unlock()
			if err != nil {
				http.Error(rw, "500 Internal Server Error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			io.WriteString(rw, "success")
			return
		case "":
			fallthrough
		default:
		}
	BADREQ:
		http.Error(rw, "400 BAD REQUEST", http.StatusBadRequest)
	})
	return nil
}

func getfirst(key string, q *url.Values) string {
	keys, ok := (*q)[key]
	if ok {
		return keys[0]
	}
	return ""
}