package http

import (
	"net"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	C "github.com/Dreamacro/clash/constant"
)

// HTTP 代理服务器
type Listener struct {
	listener net.Listener // 监听器
	addr     string // 监听地址
	closed   bool // 监听器是否关闭
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
// 获取监听器监听地址的字符表示, TODO: 和 l.addr 的区别是?
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

func New(addr string, in chan<- C.ConnContext) (*Listener, error) {
	return NewWithAuthenticate(addr, in, true)
}

func NewWithAuthenticate(addr string, in chan<- C.ConnContext, authenticate bool) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	var c *cache.Cache
	if authenticate {
		c = cache.New(time.Second * 30)
	}

	hl := &Listener{
		listener: l,
		addr:     addr,
	}

	// 启动监听协程, 处理到达的链接请求
	go func() {
		for {
			conn, err := hl.listener.Accept()
			if err != nil {
				if hl.closed {
					break
				}
				continue
			}

			// 每个到达的请求都是在新的协程里面处理的
			go HandleConn(conn, in, c)
		}
	}()

	return hl, nil
}
