package wire

import "time"

const filetimeTicksPerSecond = uint64(10_000_000)

func TimeToFiletime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return epochFiletime + uint64(t.Unix())*filetimeTicksPerSecond + uint64(t.Nanosecond())/100
}

func FiletimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	adj := ft - epochFiletime
	secs := int64(adj / filetimeTicksPerSecond)
	nsec := int64(adj%filetimeTicksPerSecond) * 100
	return time.Unix(secs, nsec).UTC()
}

const epochFiletime = 116_444_736_000_000_000
