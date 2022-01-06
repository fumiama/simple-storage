# simple-storage
Simple Golang storage server

## Command Line
```bash
./simple-storage -l ip:port -k authkeyhex -p /route1=/path1 -p /route2=/path2 ...
```
- **-l**: listening ip&port
- **-k**: 16 bytes hex key for TEA encryption
- **-p**: add a route to serve files under path

## Query

```bash
http://server.com/routex?arg=[argument]&name=[filename]&key=[filemd5]
```
- **argument**: has/lst/get/set
- **name**: filename to has/lst/get/set
- **key**: md5 of file to set

#### Request
- **set**: post method with `TEA` encrypted data in body
- **others**: get method with query above

#### Response
- **has**: 17 bytes data, the first byte is `00`(not exist) or `01`(exist), others are file md5
- **lst**: json object of {filename: md5 bytes}
- **get**: file data in body and `md5` in header
- **set**: `success` or `exist`

## Client
> There is a client at `./client`, you should use it to access simple-storage

```go
// NewClient key is 16 bytes hex string
func NewClient(apiurl, key string) *Client

// IsFileExist return status, md5, error
func (c *Client) IsFileExist(folder, name string) (bool, *[16]byte, error)

// ListFiles return map[name]md5, error
func (c *Client) ListFiles(folder string) (m map[string][16]byte, err error)

// GetFile return data, md5, error
func (c *Client) GetFile(folder, name string) ([]byte, *[16]byte, error)

// SetFile return error
func (c *Client) SetFile(folder, name string, data []byte) error
```