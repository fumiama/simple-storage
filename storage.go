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
	"time"

	"github.com/fumiama/simple-storage/helper"
)

// handle 无法防范中间人攻击，请在安全内网使用
// isprotected: 在所有 arg 都应用 tea 加密
func handle(route, path string, isprotected bool) error {
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

	fmt.Println("perparing route", route, "with", len(dir), "files in path", path, "protected:", isprotected)
	err = db.Create(route[1:], &filemd5{})
	if err != nil {
		panic(err)
	}

	if len(dir) > n {
		ts := time.Now().UnixNano()
		_, _ = os.ReadFile(path + "/" + dir[0].Name())
		delay := (time.Now().UnixNano() - ts) / int64(n)
		fmt.Println("delay:", delay, "ns")
		for ; i < len(dir)-p; i += p {
			fmt.Println("perparing", i, "to", i+p)
			wg.Add(1)
			go func(dir []fs.DirEntry) {
				for _, e := range dir {
					if !e.IsDir() {
						var fmd5 filemd5
						dbmu.RLock()
						err = db.Find(route[1:], &fmd5, "where name="+e.Name())
						dbmu.RUnlock()
						var m [16]byte
						if err == nil {
							_, err = hex.Decode(m[:], helper.StringToBytes(fmd5.Md5))
							if err != nil {
								panic(err)
							}
						} else {
							data, err := os.ReadFile(path + "/" + e.Name())
							if err != nil {
								continue
							}
							m = md5.Sum(data)
							fmd5.Name = e.Name()
							fmd5.Md5 = hex.EncodeToString(m[:])
							go func() {
								dbmu.Lock()
								db.Insert(route[1:], &fmd5)
								dbmu.Unlock()
							}()
						}
						infolk.Lock()
						filesinfo[e.Name()] = m
						infolk.Unlock()
					}
				}
				wg.Done()
			}(dir[i : i+p])
			time.Sleep(time.Duration(delay))
		}
	}
	fmt.Println("perparing", i, "to", len(dir))
	for _, e := range dir[i:] {
		if !e.IsDir() {
			var fmd5 filemd5
			dbmu.RLock()
			err = db.Find(route[1:], &fmd5, "where name="+e.Name())
			dbmu.RUnlock()
			var m [16]byte
			if err == nil {
				_, err = hex.Decode(m[:], helper.StringToBytes(fmd5.Md5))
				if err != nil {
					panic(err)
				}
			} else {
				data, err := os.ReadFile(path + "/" + e.Name())
				if err != nil {
					continue
				}
				m = md5.Sum(data)
				fmd5.Name = e.Name()
				fmd5.Md5 = hex.EncodeToString(m[:])
				go func() {
					dbmu.Lock()
					db.Insert(route[1:], &fmd5)
					dbmu.Unlock()
				}()
			}
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
			if isprotected {
				rw.Write(mytea.Encrypt(retb))
				return
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
			if isprotected {
				rw.Write(mytea.Encrypt(dat))
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
			if isprotected {
				data, err := os.ReadFile(path + "/" + name)
				if err != nil {
					http.Error(rw, "500 Internal Server Error: "+err.Error(), http.StatusInternalServerError)
					return
				}
				rw.Write(mytea.Encrypt(data))
				return
			}
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
			go func() {
				dbmu.Lock()
				db.Insert(route[1:], &filemd5{Name: name, Md5: hex.EncodeToString(m[:])})
				dbmu.Unlock()
			}()
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
