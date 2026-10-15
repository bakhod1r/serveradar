package probe

import "syscall"

func statfs(p string) (total, free, inodes, ifree uint64, ok bool) {
	var s syscall.Statfs_t
	if syscall.Statfs(p, &s) != nil {
		return 0, 0, 0, 0, false
	}
	bs := uint64(s.Bsize)
	return s.Blocks * bs, s.Bavail * bs, s.Files, s.Ffree, true
}
