package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/Dreamacro/clash/component/auth"
)

// Error represents a SOCKS error
type Error byte

func (err Error) Error() string {
	return "SOCKS error: " + strconv.Itoa(int(err))
}

// Command is request commands as defined in RFC 1928 section 4.
type Command = uint8

const Version = 5

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      Command = 1
	CmdBind         Command = 2
	CmdUDPAssociate Command = 3
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

// MaxAddrLen is the maximum size of SOCKS address in bytes.
const MaxAddrLen = 1 + 1 + 255 + 2

// MaxAuthLen is the maximum size of user/password field in SOCKS5 Auth
const MaxAuthLen = 255

// Addr represents a SOCKS address as defined in RFC 1928 section 5.
type Addr []byte

func (a Addr) String() string {
	var host, port string

	// 协议里面的数据是大端字节序的, 这里通过位移把 16bits 的端口号计算出来

	switch a[0] {
	case AtypDomainName:
		hostLen := uint16(a[1])
		host = string(a[2 : 2+hostLen])
		port = strconv.Itoa((int(a[2+hostLen]) << 8) | int(a[2+hostLen+1]))
	case AtypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa((int(a[1+net.IPv4len]) << 8) | int(a[1+net.IPv4len+1]))
	case AtypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa((int(a[1+net.IPv6len]) << 8) | int(a[1+net.IPv6len+1]))
	}

	return net.JoinHostPort(host, port)
}

// UDPAddr converts a socks5.Addr to *net.UDPAddr
// TODO: 如果 Addr 是 AtypDomainName 的情况呢?
func (a Addr) UDPAddr() *net.UDPAddr {
	if len(a) == 0 {
		return nil
	}

	switch a[0] {
	case AtypIPv4:
		var ip [net.IPv4len]byte
		copy(ip[0:], a[1:1+net.IPv4len])
		return &net.UDPAddr{IP: net.IP(ip[:]), Port: int(binary.BigEndian.Uint16(a[1+net.IPv4len : 1+net.IPv4len+2]))}
	case AtypIPv6:
		var ip [net.IPv6len]byte
		copy(ip[0:], a[1:1+net.IPv6len])
		return &net.UDPAddr{IP: net.IP(ip[:]), Port: int(binary.BigEndian.Uint16(a[1+net.IPv6len : 1+net.IPv6len+2]))}
	}

	// Other Atyp
	return nil
}

// SOCKS errors as defined in RFC 1928 section 6.
const (
	ErrGeneralFailure       = Error(1)
	ErrConnectionNotAllowed = Error(2)
	ErrNetworkUnreachable   = Error(3)
	ErrHostUnreachable      = Error(4)
	ErrConnectionRefused    = Error(5)
	ErrTTLExpired           = Error(6)
	ErrCommandNotSupported  = Error(7)
	ErrAddressNotSupported  = Error(8)
)

// Auth errors used to return a specific "Auth failed" error
var ErrAuth = errors.New("auth failed")

type User struct {
	Username string
	Password string
}

// ServerHandshake fast-tracks SOCKS initialization to get target address to connect on server side.
func ServerHandshake(rw net.Conn, authenticator auth.Authenticator) (addr Addr, command Command, err error) {
	// Read RFC 1928 for request and reply structure and sizes.
	buf := make([]byte, MaxAddrLen)

	// read VER, NMETHODS, METHODS
	if _, err = io.ReadFull(rw, buf[:2]); err != nil {
		return
	}

	// read METHODS
	nmethods := buf[1]
	if _, err = io.ReadFull(rw, buf[:nmethods]); err != nil {
		return
	}

	// write VER METHOD
	// 用户名/密码认证: https://www.rfc-editor.org/rfc/rfc1929
	if authenticator != nil {
		// 写死的支持 用户名+密码 认证形式 = 0x02
		if _, err = rw.Write([]byte{5, 2}); err != nil {
			return
		}

		// 下面是客户端收到认证方法响应之后, 发送过来的认证内容
		// https://blog.csdn.net/red10057/article/details/8565011

		// Get header
		// 第一字节是 VER 字节, 在这里没用
		// 第二个字节是用户名长度 - ULen
		header := make([]byte, 2)
		if _, err = io.ReadFull(rw, header); err != nil {
			return
		}

		authBuf := make([]byte, MaxAuthLen)

		// Get username
		userLen := int(header[1])
		if userLen <= 0 {
			rw.Write([]byte{1, 1})
			err = ErrAuth
			return
		}

		if _, err = io.ReadFull(rw, authBuf[:userLen]); err != nil {
			return
		}
		user := string(authBuf[:userLen])

		// Get password
		if _, err = rw.Read(header[:1]); err != nil {
			return
		}

		passLen := int(header[0])
		if passLen <= 0 {
			rw.Write([]byte{1, 1})
			err = ErrAuth
			return
		}

		if _, err = io.ReadFull(rw, authBuf[:passLen]); err != nil {
			return
		}
		pass := string(authBuf[:passLen])

		// Verify
		if ok := authenticator.Verify(string(user), string(pass)); !ok {
			rw.Write([]byte{1, 1})
			err = ErrAuth
			return
		}

		// Response auth state
		if _, err = rw.Write([]byte{1, 0}); err != nil {
			return
		}
	} else {
		// 0x00 表示无需认证
		if _, err = rw.Write([]byte{5, 0}); err != nil {
			return
		}
	}

	// 上面是认证请求完成. 后续开始处理 socks5 定义的 command

	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err = io.ReadFull(rw, buf[:3]); err != nil {
		return
	}

	command = buf[1]
	addr, err = ReadAddr(rw, buf) // 注意这里从客户端发来的数据里面, 获取到了目标服务器的ip/port信息
	if err != nil {
		return
	}

	switch command {
	case CmdConnect, CmdUDPAssociate:
		// Acquire server listened address info
		// 这里拿到的是 socks5 proxy server 的地址信息
		localAddr := ParseAddr(rw.LocalAddr().String())
		if localAddr == nil {
			err = ErrAddressNotSupported
		} else {
			// write VER REP RSV ATYP BND.ADDR BND.PORT
			// 这里直接就是写死的连接(到目标服务器, 实际上还没有发起这个链接)成功
			// BND.ADDR + BND.PORT 本来应该是实际服务器的信息, 这里也被替换成 socks5 proxy 服务器的信息
			// https://www.seeull.com/archives/24.html
			_, err = rw.Write(bytes.Join([][]byte{{5, 0, 0}, localAddr}, []byte{}))
		}
	case CmdBind:
		fallthrough
	default:
		err = ErrCommandNotSupported
	}

	return
}

// ClientHandshake fast-tracks SOCKS initialization to get target address to connect on client side.
// TODO: 看一下 UDP 的数据交互
func ClientHandshake(rw io.ReadWriter, addr Addr, command Command, user *User) (Addr, error) {
	buf := make([]byte, MaxAddrLen)
	var err error

	// VER, NMETHODS, METHODS
	// 响应是否需要认证
	if user != nil {
		_, err = rw.Write([]byte{5, 1, 2})
	} else {
		_, err = rw.Write([]byte{5, 1, 0})
	}
	if err != nil {
		return nil, err
	}

	// VER, METHOD
	if _, err := io.ReadFull(rw, buf[:2]); err != nil {
		return nil, err
	}

	if buf[0] != 5 {
		return nil, errors.New("SOCKS version error")
	}

	if buf[1] == 2 {
		if user == nil {
			return nil, ErrAuth
		}

		// -- RFC 1929 --
		// password protocol version
		authMsg := &bytes.Buffer{}
		authMsg.WriteByte(1)
		authMsg.WriteByte(uint8(len(user.Username)))
		authMsg.WriteString(user.Username)
		authMsg.WriteByte(uint8(len(user.Password)))
		authMsg.WriteString(user.Password)

		// 这是给客户端相应的认证信息
		if _, err := rw.Write(authMsg.Bytes()); err != nil {
			return nil, err
		}

		// 获取到客户端对认证信息的处理结果 -- VER STATUS
		if _, err := io.ReadFull(rw, buf[:2]); err != nil {
			return nil, err
		}

		if buf[1] != 0 {
			return nil, errors.New("rejected username/password")
		}
	} else if buf[1] != 0 {
		return nil, errors.New("SOCKS need auth")
	}

	// 上面是认证交互, 搞完了之后开始正式处理指令内容

	// VER, CMD, RSV, ADDR
	if _, err := rw.Write(bytes.Join([][]byte{{5, command, 0}, addr}, []byte{})); err != nil {
		return nil, err
	}

	// VER, REP, RSV
	if _, err := io.ReadFull(rw, buf[:3]); err != nil {
		return nil, err
	}

	return ReadAddr(rw, buf)
}

func ReadAddr(r io.Reader, b []byte) (Addr, error) {
	if len(b) < MaxAddrLen {
		return nil, io.ErrShortBuffer
	}

	// 第一个字节是 地址 类型
	_, err := io.ReadFull(r, b[:1]) // read 1st byte for address type
	if err != nil {
		return nil, err
	}

	// 注意看里面的 ReadFull 调用都有包含端口的信息

	switch b[0] {
	case AtypDomainName:
		_, err = io.ReadFull(r, b[1:2]) // read 2nd byte for domain length
		if err != nil {
			return nil, err
		}
		domainLength := uint16(b[1])
		_, err = io.ReadFull(r, b[2:2+domainLength+2])
		return b[:1+1+domainLength+2], err
	case AtypIPv4:
		_, err = io.ReadFull(r, b[1:1+net.IPv4len+2])
		return b[:1+net.IPv4len+2], err
	case AtypIPv6:
		_, err = io.ReadFull(r, b[1:1+net.IPv6len+2])
		return b[:1+net.IPv6len+2], err
	}

	return nil, ErrAddressNotSupported
}

// SplitAddr slices a SOCKS address from beginning of b. Returns nil if failed.
func SplitAddr(b []byte) Addr {
	addrLen := 1
	if len(b) < addrLen {
		return nil
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 2 {
			return nil
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case AtypIPv4:
		addrLen = 1 + net.IPv4len + 2
	case AtypIPv6:
		addrLen = 1 + net.IPv6len + 2
	default:
		return nil

	}

	if len(b) < addrLen {
		return nil
	}

	return b[:addrLen]
}

// ParseAddr parses the address in string s. Returns nil if failed.
// 组合出来在 socks5 协议中使用的 ATYP + BND.ADDR + BND.PORT 地址
func ParseAddr(s string) Addr {
	var addr Addr
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = AtypIPv4
			copy(addr[1:], ip4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = AtypIPv6
			copy(addr[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil
		}
		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = AtypDomainName
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}

	addr[len(addr)-2], addr[len(addr)-1] = byte(portnum>>8), byte(portnum)

	return addr
}

// ParseAddrToSocksAddr parse a socks addr from net.addr
// This is a fast path of ParseAddr(addr.String())
func ParseAddrToSocksAddr(addr net.Addr) Addr {
	var hostip net.IP
	var port int
	if udpaddr, ok := addr.(*net.UDPAddr); ok {
		hostip = udpaddr.IP
		port = udpaddr.Port
	} else if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		hostip = tcpaddr.IP
		port = tcpaddr.Port
	}

	// fallback parse
	if hostip == nil {
		return ParseAddr(addr.String())
	}

	var parsed Addr
	if ip4 := hostip.To4(); ip4.DefaultMask() != nil {
		parsed = make([]byte, 1+net.IPv4len+2)
		parsed[0] = AtypIPv4
		copy(parsed[1:], ip4)
		binary.BigEndian.PutUint16(parsed[1+net.IPv4len:], uint16(port))
	} else {
		parsed = make([]byte, 1+net.IPv6len+2)
		parsed[0] = AtypIPv6
		copy(parsed[1:], hostip)
		binary.BigEndian.PutUint16(parsed[1+net.IPv6len:], uint16(port))
	}

	return parsed
}

// DecodeUDPPacket split `packet` to addr payload, and this function is mutable with `packet`
func DecodeUDPPacket(packet []byte) (addr Addr, payload []byte, err error) {
	if len(packet) < 5 {
		err = errors.New("insufficient length of packet")
		return
	}

	// packet[0] and packet[1] are reserved
	if !bytes.Equal(packet[:2], []byte{0, 0}) {
		err = errors.New("reserved fields should be zero")
		return
	}

	if packet[2] != 0 /* fragments */ {
		err = errors.New("discarding fragmented payload")
		return
	}

	addr = SplitAddr(packet[3:])
	if addr == nil {
		err = errors.New("failed to read UDP header")
	}

	payload = packet[3+len(addr):]
	return
}

func EncodeUDPPacket(addr Addr, payload []byte) (packet []byte, err error) {
	if addr == nil {
		err = errors.New("address is invalid")
		return
	}
	packet = bytes.Join([][]byte{{0, 0, 0}, addr, payload}, []byte{})
	return
}
