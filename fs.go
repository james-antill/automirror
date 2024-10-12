package automirror

import (
	"io/fs"
	"slices"
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

type named interface {
	Name() string
}

// Does both dir/file...
func fSnodeBinaryLookup[T named](ts []T, t T) (int, bool) {
	return slices.BinarySearchFunc(ts, t, func(a, b T) int {
		return strings.Compare(a.Name(), b.Name())
	})
}

// Does both dir/file...
func fSnodeBinaryInsert[T named](ts []T, t T) []T {
	if len(ts) == 0 {
		return append(ts, t)
	}

	i, _ := fSnodeBinaryLookup(ts, t)

	return slices.Insert(ts, i, t)
}

func (n *fSnodeD) lookupDir(name string) *fSnodeD {
	t := &fSnodeD{name: name}
	i, found := fSnodeBinaryLookup(n.cdirs, t)

	if found {
		return n.cdirs[i]
	}

	return nil
}
func (n *fSnodeD) lookupFile(name string) *fSnodeF {
	t := &fSnodeF{name: name}
	i, found := fSnodeBinaryLookup(n.cfiles, t)

	if found {
		return n.cfiles[i]
	}

	return nil
}

func (n *fSnodeD) addDir(nd *fSnodeD) {
	n.cdirs = fSnodeBinaryInsert[*fSnodeD](n.cdirs, nd)
}

func (n *fSnodeD) addFile(nf *fSnodeF) {
	n.cfiles = fSnodeBinaryInsert[*fSnodeF](n.cfiles, nf)
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

	pDirNode *fSnodeD
	pDirPath []string

	nds []fSnodeD
	nfs []fSnodeF
}

func NewRoot() *RootFS {
	return &RootFS{root: &fSnodeD{name: "/"}}
}

const cachePDir = true

func (r *RootFS) lookupPDir(path string, create bool) (*fSnodeD, string) {
	if path[0] == '/' {
		path = path[1:]
	}

	d := r.root

	opaths := strings.Split(path, "/")
	paths := opaths
	// See if we've cache a parent of the tree...
	if r.pDirNode != nil && len(paths) > len(r.pDirPath) {
		if slices.Equal(r.pDirPath, paths[:len(r.pDirPath)]) {
			d = r.pDirNode
			paths = paths[len(r.pDirPath):]
		}
	}

	for len(paths) > 1 {
		n := d.lookupDir(paths[0])
		if n == nil && create {
			n = r.allocDirectory(paths[0], 0)
			d.addDir(n)
		}
		if n == nil {
			return nil, ""
		}

		d = n
		paths = paths[1:]
	}

	if cachePDir {
		r.pDirNode = d
		r.pDirPath = opaths[:len(opaths)-1]
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

// const block_alloc_size int = 0
// const block_alloc_size int = 1000
const block_alloc_size int = ((1024 * 8) - 32) / 24

func (r *RootFS) allocDirectory(name string, mtime int64) *fSnodeD {
	if block_alloc_size > 0 {
		if len(r.nds) == 0 {
			r.nds = make([]fSnodeD, block_alloc_size)
		}
		nd := &r.nds[0]
		r.nds = r.nds[1:]
		nd.name = name
		nd.mtimeSecs = mtime
		return nd
	} else {
		nd := &fSnodeD{name: name, mtimeSecs: mtime}
		return nd
	}
}

func (r *RootFS) AddDirectory(path string, mtime int64) {
	d, name := r.lookupPDir(path, true)

	nd := r.allocDirectory(name, mtime)
	d.addDir(nd)
}

func (r *RootFS) AddFile(path string, mtime int64, size int64) {
	d, name := r.lookupPDir(path, true)

	if block_alloc_size > 0 {
		if len(r.nfs) == 0 {
			r.nfs = make([]fSnodeF, block_alloc_size)
		}
		nf := &r.nfs[0]
		r.nfs = r.nfs[1:]
		nf.name = name
		nf.mtimeSecs = mtime
		nf.size = size
		d.addFile(nf)
	} else {
		nf := &fSnodeF{name: name, mtimeSecs: mtime, size: size}
		d.addFile(nf)
	}
}

func (r *RootFS) NumDirs() int64 {
	return r.root.numDirs()
}
func (r *RootFS) NumFiles() int64 {
	return r.root.numFiles()
}
