package automirror

import (
	"io/fs"
	"strings"
	"time"
)

type FSnode interface {
	fs.FileInfo

	SetMtimeS(int64) // Set the mtime, used for dirs.

	Children() []FSnode // For directories only.
	// Lookup(name string) FSnode // For directories only.

	MtimeS() int64 // ModTime() int64 seconds only.
}

// FSnodeD Directory
type fSnodeD struct {
	name      string
	mtimeSecs int64

	cdirs  []*fSnodeD // Directories
	cfiles []*fSnodeF // Files
}

func (n *fSnodeD) Name() string {
	return n.name
}
func (n *fSnodeD) Size() int64 {
	var size int64

	for _, c := range n.cdirs {
		size += c.Size()
	}
	for _, c := range n.cfiles {
		size += c.Size()
	}
	return size
}
func (n *fSnodeD) Mode() fs.FileMode {
	return 0755
}
func (n *fSnodeD) MtimeS() int64 {
	return n.mtimeSecs
}
func (n *fSnodeD) ModTime() time.Time {
	return time.Unix(n.MtimeS(), 0)
}
func (n *fSnodeD) IsDir() bool           { return true }
func (n *fSnodeD) Sys() any              { return nil }
func (n *fSnodeD) SetMtimeS(mtime int64) { n.mtimeSecs = mtime }
func (n *fSnodeD) Children() []FSnode {
	var ret []FSnode

	for _, c := range n.cdirs {
		ret = append(ret, c)
	}
	for _, c := range n.cfiles {
		ret = append(ret, c)
	}

	return ret
}

func (n *fSnodeD) lookupDir(name string) *fSnodeD {
	// FIXME: Sort...
	for _, c := range n.cdirs {
		if name == c.Name() {
			return c
		}
	}
	return nil
}
func (n *fSnodeD) lookupFile(name string) *fSnodeF {
	// FIXME: Sort...
	for _, c := range n.cfiles {
		if name == c.Name() {
			return c
		}
	}
	return nil
}
func (n *fSnodeD) addBlankDir(name string) *fSnodeD {
	// FIXME: Sort...
	ret := &fSnodeD{name: name}
	n.cdirs = append(n.cdirs, ret)
	return ret
}

func (n *fSnodeD) addDir(name string, mtime int64) *fSnodeD {
	// FIXME: Sort...
	ret := &fSnodeD{name: name, mtimeSecs: mtime}
	n.cdirs = append(n.cdirs, ret)
	return ret
}

func (n *fSnodeD) addFile(name string, mtime int64, size int64) *fSnodeF {
	// FIXME: Sort...
	ret := &fSnodeF{name: name, mtimeSecs: mtime, size: size}
	n.cfiles = append(n.cfiles, ret)
	return ret
}

func (n *fSnodeD) numDirs() int64 {
	var ret int64

	for _, c := range n.cdirs {
		ret += 1
		ret += c.numDirs()
	}
	return ret
}
func (n *fSnodeD) numFiles() int64 {
	var ret int64

	ret += int64(len(n.cfiles))
	for _, c := range n.cdirs {
		ret += c.numFiles()
	}
	return ret
}

// FSnodeF File
type fSnodeF struct {
	name      string
	size      int64
	mtimeSecs int64
}

func (n *fSnodeF) Name() string {
	return n.name
}
func (n *fSnodeF) Size() int64 {
	return n.size
}
func (n *fSnodeF) Mode() fs.FileMode {
	return 0644
}
func (n *fSnodeF) MtimeS() int64 {
	return n.mtimeSecs
}
func (n *fSnodeF) ModTime() time.Time {
	return time.Unix(n.mtimeSecs, 0)
}
func (n *fSnodeF) IsDir() bool           { return false }
func (n *fSnodeF) Sys() any              { return nil }
func (n *fSnodeF) SetMtimeS(mtime int64) { n.mtimeSecs = mtime }
func (n *fSnodeF) Children() []FSnode    { return nil }

// FSnodeF Root of a file tree of directories/files
type RootFS struct {
	root *fSnodeD
}

func NewRoot() *RootFS {
	return &RootFS{&fSnodeD{name: "/"}}
}

func (r *RootFS) lookupPDir(path string, create bool) (*fSnodeD, string) {
	if path[0] == '/' {
		path = path[1:]
	}

	d := r.root

	paths := strings.Split(path, "/")
	for len(paths) > 1 {
		n := d.lookupDir(paths[0])
		if n == nil && create {
			n = d.addBlankDir(paths[0])
		}
		if n == nil {
			return nil, ""
		}

		d = n
		paths = paths[1:]
	}

	return d, paths[0]
}

func (r *RootFS) RootDir() FSnode {
	return r.root
}

func (r *RootFS) Lookup(path string) (FSnode, bool) {
	d, name := r.lookupPDir(path, false)

	if d == nil {
		return nil, false
	}

	nd := d.lookupDir(name)
	if nd != nil {
		return nd, true
	}

	nf := d.lookupFile(name)
	if nf != nil {
		return nf, true
	}

	return nil, false
}

func (r *RootFS) AddDirectory(path string, mtime int64) {
	d, name := r.lookupPDir(path, true)

	d.addDir(name, mtime)
}
func (r *RootFS) AddFile(path string, mtime int64, size int64) {
	d, name := r.lookupPDir(path, true)

	d.addFile(name, mtime, size)
}

func (r *RootFS) NumDirs() int64 {
	return r.root.numDirs()
}
func (r *RootFS) NumFiles() int64 {
	return r.root.numFiles()
}
