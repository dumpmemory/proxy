package socks5

// Reply reply
type Reply byte

const (
	// ReplyOK ok
	ReplyOK = Reply(0x00)
	// ReplyConnectionRefused connection refused
	ReplyConnectionRefused = Reply(0x01)
	// ReplyRuleDisabled rule disable
	ReplyRuleDisabled = Reply(0x02)
	// ReplyNetworkUnavailable net unavailable
	ReplyNetworkUnavailable = Reply(0x03)
	// ReplyHostUnavailable host unavailable
	ReplyHostUnavailable = Reply(0x04)
	// ReplyResetByPeer connection reset by peer
	ReplyResetByPeer = Reply(0x05)
	// ReplyTTLExpired ttl expired
	ReplyTTLExpired = Reply(0x06)
	// ReplyUnsupportCmd unsupport command
	ReplyUnsupportCmd = Reply(0x07)
	// ReplyUnsupportAddr unsupport address
	ReplyUnsupportAddr = Reply(0x08)
)

func (r Reply) String() string {
	switch r {
	case ReplyOK:
		return "ok"
	case ReplyConnectionRefused:
		return "connection refused"
	case ReplyRuleDisabled:
		return "rule mismatch"
	case ReplyNetworkUnavailable:
		return "network unavailable"
	case ReplyHostUnavailable:
		return "host unavailable"
	case ReplyResetByPeer:
		return "connection reset by peer"
	case ReplyTTLExpired:
		return "ttl expired"
	case ReplyUnsupportCmd:
		return "unsupported command"
	case ReplyUnsupportAddr:
		return "unsupported address"
	}
	return ""
}
