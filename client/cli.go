package client

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unsafe"

	tea "github.com/fumiama/gofastTEA"
)

type Client struct {
	apiurl string
	tea    tea.TEA
}

// NewClient key is 16 bytes hex string
func NewClient(apiurl, key string) *Client {
	if len(key) != 32 {
		return nil
	}
	kb, err := hex.DecodeString(key)
	if err != nil {
		return nil
	}
	return &Client{
		apiurl: strings.TrimSuffix(apiurl, "/"),
		tea:    tea.NewTeaCipherLittleEndian(kb),
	}
}

// IsFileExist return status, md5, error
func (c *Client) IsFileExist(folder, name string) (bool, *[16]byte, error) {
	u := c.apiurl + "/" + folder + "?arg=has&name=" + url.QueryEscape(name)
	r, err := http.Get(u)
	if err != nil {
		return false, nil, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return false, nil, err
	}
	if len(b) != 17 {
		return false, nil, os.ErrInvalid
	}
	if b[0] == 0 {
		return false, nil, nil
	}
	b = b[1:]
	return true, (*[16]byte)(unsafe.Pointer(&b)), nil
}

// ListFiles return map[name]md5, error
func (c *Client) ListFiles(folder string) (m map[string][16]byte, err error) {
	u := c.apiurl + "/" + folder + "?arg=lst"
	r, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	m = make(map[string][16]byte)
	err = json.Unmarshal(b, &m)
	return
}

// GetFile return data, md5, error
func (c *Client) GetFile(folder, name string) ([]byte, *[16]byte, error) {
	u := c.apiurl + "/" + folder + "?arg=get&name=" + url.QueryEscape(name)
	r, err := http.Get(u)
	if err != nil {
		return nil, nil, err
	}

	m := r.Header.Get("md5")
	if m == "" {
		return nil, nil, os.ErrInvalid
	}
	ms, err := url.QueryUnescape(m)
	if err != nil {
		return nil, nil, err
	}
	if len(ms) != 16 {
		return nil, nil, os.ErrInvalid
	}

	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, err
	}

	return b, (*[16]byte)(unsafe.Pointer(&ms)), nil
}

// SetFile return error
func (c *Client) SetFile(folder, name string, data []byte) error {
	m := md5.Sum(data)
	u := c.apiurl + "/" + folder + "?arg=set&name=" + url.QueryEscape(name) + "&key=" + hex.EncodeToString(m[:])
	data = c.tea.Encrypt(data)
	r, err := http.Post(u, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		return err
	}
	_, err = io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return r.Body.Close()
}
