package snowflake

import (
	"sync"
	"time"
)

const (
	epoch        = int64(1609459200000) // 设置起始时间戳（毫秒级），例如：2021-01-01 00:00:00
	nodeBits     = 10                   // 设置工作节点ID位数
	sequenceBits = 12                   // 设置序列号位数
)

type Snowflake struct {
	mu        sync.Mutex
	timestamp int64
	nodeID    int64
	sequence  int64
}

func New(nodeID int64) *Snowflake {
	return &Snowflake{
		nodeID: nodeID,
	}
}

func (s *Snowflake) Generate() int64 {
	// 生成唯一ID的函数

	s.mu.Lock()         // 加锁
	defer s.mu.Unlock() // 解锁

	now := time.Now().UnixNano() / 1000000 // 当前时间戳（毫秒级）

	if s.timestamp == now {
		// 如果当前时间戳与Snowflake对象的时间戳相等，则序列号加1并进行溢出处理
		s.sequence = (s.sequence + 1) & ((1 << sequenceBits) - 1)
		if s.sequence == 0 {
			// 如果序列号溢出，则等待下一毫秒直到当前时间戳变大
			for now <= s.timestamp {
				now = time.Now().UnixNano() / 1000000 // 获取当前时间戳
			}
		}
	} else {
		// 如果当前时间戳与Snowflake对象的时间戳不等，则将序列号和时间戳都重置为初始值
		s.sequence = 0
	}
	s.timestamp = now // 更新Snowflake对象的时间戳

	// 生成ID
	id := ((now - epoch) << (nodeBits + sequenceBits)) | (s.nodeID << sequenceBits) | s.sequence
	return id

}
