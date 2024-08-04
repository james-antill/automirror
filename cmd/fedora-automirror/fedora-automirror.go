package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/james-antill/automirror"
	roc "github.com/james-antill/rename-on-close"
)

const version = "0.8.1"

// See: https://www.datatables.net
const cssStyle = `
   <script
      src="https://code.jquery.com/jquery-3.3.1.slim.min.js"
      integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo"
      crossorigin="anonymous">
    </script>

    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.22/css/jquery.dataTables.css">
    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.22/js/jquery.dataTables.js"></script>

        <link rel="dns-prefetch" href="https://fonts.googleapis.com">
            <style>
@import url('https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,700');
body {
        font-family:'Source Sans Pro', sans-serif;
        margin:0;
}

h1,h2,h3,h4,h5,h6 {
        margin:0;
}

td.dtclass, th.dtclass {
  display: none;
}
            </style>
`

var counter int

func _fnHEAD(url string, mtime time.Time, size int64) bool {
	resp, err := http.Head(url)
	if err != nil {
		return false
	}

	if resp.StatusCode == 200 && resp.ContentLength == size {
		pt, err := http.ParseTime(resp.Header.Get("Last-Modified"))
		if err == nil && pt.Equal(mtime) {
			return true
		}
	}

	return false
}

func fnsync(fs *fedStore, ufname string, ent automirror.FSnode) (
	io.Closer, io.ReadSeeker, error) {
	lfname := fs.prefix[1:] + ufname
	upstream := fs.upstream
	local := false

	fmt.Println("Req:", lfname)

	fi, err := os.Stat(lfname)
	if err == nil { // File exists...
		if ent != nil {
			// We can't do fi.ModTime().Equal(ent.ModTime()) &&
			// ...because in the fullfiletimelist data the mtime is actually:
			// max(mtime, ctime)
			if fi.Size() == ent.Size() {
				local = true
				// } else {
				//	fmt.Println("JDBG:", "tm:", fi.ModTime(), ent.ModTime())
				//	fmt.Println("JDBG:", "sz:", fi.Size(), ent.Size())
			}
		} else {
			// Use if-modified-since for a single call?
			local = _fnHEAD(upstream+"/"+ufname, fi.ModTime(), fi.Size())
			if local && ufname == fs.fftl {
				fs.indextm = fi.ModTime()
			}
		}
	}

	if !local {
		dname := filepath.Dir(lfname)
		os.MkdirAll(dname, 0755)
		nf, err := roc.Create(lfname)
		if err != nil {
			return nil, nil, err
		}
		defer nf.Close()

		resp, err := http.Get(upstream + "/" + ufname)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, nil, http.ErrMissingFile
		}

		fs.incDwn()
		tm := mtime2ui(time.Now().Unix())
		fmt.Fprintln(os.Stdout, " -> Downloading:", tm, resp.ContentLength, ufname)

		if _, err := io.Copy(nf, resp.Body); err != nil {
			return nil, nil, err
		}
		if err := nf.CloseRename(); err != nil {
			return nil, nil, err
		}

		pt, err := http.ParseTime(resp.Header.Get("Last-Modified"))
		if err == nil {
			_ = os.Chtimes(lfname, pt, pt)
			if ufname == fs.fftl {
				fs.indextm = pt
			}
		}
	}

	fo, err := os.Open(lfname)
	return fo, fo, err
}

func expect(bior *bufio.Reader, expected []byte) error {
	line, prefix, err := bior.ReadLine()

	if err != nil {
		return err
	}
	if prefix {
		return fmt.Errorf("Bad line (too long)")
	}

	if !bytes.Equal(line, expected) {
		return fmt.Errorf("Bad line (%s != %s)", string(expected), string(line))
	}

	return nil
}

func b2i(b []byte) int64 {
	return s2i(string(b))
}

func s2i(b string) int64 {
	v, err := strconv.ParseInt(b, 10, 0)
	if err != nil {
		return -1
	}
	return v
}

func mtime2ui(mtime int64) string {
	return time.Unix(mtime, 0).UTC().Format("2006-01-02 15:04:05")
}

// Copied from mtree -----------
// UI names for KiloBytes etc.
const (
	KB = 1000
	MB = KB * 1000
	GB = MB * 1000
	TB = GB * 1000
)

// round use like so: "%.1f", round(f, 0.1) or "%.0f", round(f, 1)
// Otherwise 9.9999 is < 10 but "%.1f" will give "10.0"
func round(x, unit float64) float64 {
	return float64(int64(x/unit+0.5)) * unit
}

// What we want is useful level of information. Eg.
// 999b
// 1.2KB
//  22KB
// 222KB
// 1.2MB

func fmtSprint(f float64, ext string) string {
	rf := round(f, 0.1)
	if f == float64(int(f)) || rf >= 10 {
		return fmt.Sprintf("%3d%s", int(rf), ext)
	}
	return fmt.Sprintf("%.1f%s", rf, ext)
}

func formatFKB(f float64) string {
	ext := "b "
	switch {
	case f >= TB:
		f /= TB
		ext = "TB"
	case f >= GB:
		f /= GB
		ext = "GB"
	case f >= MB:
		f /= MB
		ext = "MB"
	case f >= KB:
		f /= KB
		ext = "KB"
	}
	return fmtSprint(f, ext)
}
func formatKB(i int64) string {
	return formatFKB(float64(i))
}

func size2ui(size int64) string {
	return formatKB(int64(size))
}

type fedStore struct {
	upstream string
	prefix   string
	fftl     string

	beg     time.Time
	indextm time.Time

	counter   int // Number of requests
	downloads int // Number of pass through downloads
	mutex     sync.Mutex

	fdata *automirror.RootFS
}

func NewFedstore(upstream, prefix, fftl string) *fedStore {
	var ret fedStore

	ret.upstream = upstream
	ret.prefix = prefix
	ret.fftl = fftl

	ret.beg = time.Now()
	ret.fdata = automirror.NewRoot()

	return &ret
}

func (fs *fedStore) incReq() {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	fs.counter++
}

func (fs *fedStore) getReq() int {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.counter
}

func (fs *fedStore) incDwn() {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	fs.downloads++
}

func (fs *fedStore) getDwn() int {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.downloads
}

type httpDent struct {
	name string

	mtime int64
	size  int64

	isdir bool
}

// breadcrumpsSplit Take a path and emit html that gives breadcrumbs
func breadcrumpsSplit(fs *fedStore, path string) string {
	top := `<a href="/">/</a> `

	if path == "" {
		return top + fs.prefix[1:len(fs.prefix)-1]
	}

	bcs := strings.Split(fs.prefix[1:]+path, "/")

	ret := ""
	i := len(bcs) - 1
	ret = bcs[i]
	orev := "../"
	crev := orev
	for i--; i >= 0; i-- {
		// Walk the path backwards...
		bc := bcs[i]
		prv := fmt.Sprintf(`<a href="%s">%s</a> / `, crev, bc)
		ret = prv + ret
		crev = crev + orev
	}

	return top + ret
}

func (fs *fedStore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	fs.incReq()

	// This is the path within the Store. Eg. "/Fedora/linux/" becomes "linux/"
	path := strings.TrimPrefix(req.URL.Path, fs.prefix)
	fmt.Println("URL:", req.URL.Path)
	if path == "" { // See hack below...
		path = "/"
	}

	if strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
		// "" is the root of the Store...
		dent := fs.fdata.RootDir()
		if path != "" {
			n, ok := fs.fdata.Lookup(path)
			if !ok || !n.IsDir() {
				http.NotFound(w, req)
				return
			}
			dent = n
		}

		// Show a dir. listing. Again see: https://www.datatables.net
		w.Header().Set("Content-Type", "text/html")

		fmt.Fprintf(w, `<html> 
		<head> <title> UP: %s </title> %s </head>
		<body>
		<h4> Mirror of: %s </h4>
		<h1> Upstream Path: %s </h1>

<table id="dirdata" style="compact">
 <thead>
  <tr>
   <th>Name</th>
   <th>Last Modified</th>
   <th>Size</th>
  </tr>
 </thead>
 <tbody>
 `, path, cssStyle, fs.upstream+"/"+path, breadcrumpsSplit(fs, path))

		dpath := path
		if path != "" {
			dpath += "/"
		}
		// FIXME: Add the fs.fftl file for the root?
		ents := dent.Children()

		sort.Slice(ents, func(i, j int) bool {
			// rpmvercmp?
			in := s2i(ents[i].Name())
			jn := s2i(ents[j].Name())
			if in != -1 && jn != -1 {
				return in-jn < 0
			}
			return strings.Compare(ents[i].Name(), ents[j].Name()) < 0
		})

		fmt.Fprintf(w, `<tr>
		<td> <a href="%s/">%s/</a> </td> <td>%s</td> <td>-</td>
		</tr> `, "..", "..", "-")

		for _, val := range ents {
			if val.IsDir() {
				// Print a directory...
				fmt.Fprintf(w, `<tr>
<td> <a href="%s/">%s/</a> </td> <td>%s</td> <td>%s</td>
</tr> `, val.Name(), val.Name(), mtime2ui(val.MtimeS()), size2ui(val.Size()))
			} else {
				// Print a file...
				fmt.Fprintf(w, `<tr>
<td> <a href="%s">%s</a> </td> <td>%s</td> <td>%s</td>
</tr> `, val.Name(), val.Name(), mtime2ui(val.MtimeS()), size2ui(val.Size()))
			}
		}

		fmt.Fprintf(w, `
</tbody>
</table>
</body>
        <script>
        $(document).ready(
            function() {
                $('#dirdata').DataTable(
                    {
                        "paging" : false,
						columns: [
							{ orderSequence: ['', 'asc', 'desc'] },
							{ orderSequence: ['', 'asc', 'desc'] },
							{ orderSequence: ['', 'asc', 'desc'] }
						],
                        "order": []
                    }
                );
            }
        );
        </script>
</html>
`)
		return
	}

	val, ok := fs.fdata.Lookup(path)
	if !ok {
		http.NotFound(w, req)
		return
	}
	if val.IsDir() {
		path := req.URL.Path + "/"
		http.Redirect(w, req, path, http.StatusMovedPermanently)
		return
	}

	ioc, ior, err := fnsync(fs, path, val)
	defer ioc.Close()
	if err != nil {
		// ErrMissingFile ?
		panic(http.ErrAbortHandler)
	}

	mtime := val.ModTime()
	tm := mtime2ui(time.Now().Unix())
	fmt.Println(" -> Serving:", tm, req.URL.Path)
	http.ServeContent(w, req, filepath.Base(req.URL.Path), mtime, ior)
	tm = mtime2ui(time.Now().Unix())
	fmt.Println(" -> Done:", tm, req.URL.Path)
}

func _setup(fs *fedStore) {
	ioc, ior, err := fnsync(fs, fs.fftl, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't get/load file list (%s): %s\n", fs.upstream, err)
		os.Exit(1)
	}
	defer ioc.Close()

	bior := bufio.NewReader(ior)

	var expected_err error
	_expect := func(expected []byte) {
		if expected_err != nil {
			return
		}
		expected_err = expect(bior, expected)
	}

	_expect([]byte("[Version]"))
	_expect([]byte("2"))
	_expect([]byte(""))
	_expect([]byte("[Files]"))

	err = expected_err
	if err != nil {
		fmt.Fprintf(os.Stderr, "Bad file list (%s): %s\n", fs.upstream, err)
		os.Exit(1)
	}

	// Now it's a list of
	// <timestamp> \t <type> \t <size> \t <name>
	// 1717564457	f	282	linux/extras/README

	for num := 1; true; num++ {
		line, prefix, err := bior.ReadLine()

		if err == nil && prefix { // Line too big...
			err = fmt.Errorf("Bad line (too long)")
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Bad file list (%s:%d): %s\n", fs.upstream, 4+num, err)
			os.Exit(1)

		}

		if len(line) == 0 {
			// Don't care about checksums for isos etc.
			break
		}

		sline := bytes.Split(line, []byte{'\t'})
		if len(sline) != 4 {
			err = fmt.Errorf("Bad line (bad File)")
			fmt.Fprintf(os.Stderr, "Bad file list (%s:%d): %s\n", fs.upstream, 4+num, err)
			os.Exit(1)
		}
		fmtime, ftype, fsize, fname := sline[0], sline[1], sline[2], sline[3]

		switch string(ftype) {
		case "f":
			fs.fdata.AddFile(string(fname), b2i(fmtime), b2i(fsize))
		case "d":
			sfname := string(fname)
			n, ok := fs.fdata.Lookup(sfname)
			if ok {
				n.SetMtimeS(b2i(fmtime))
			} else {
				fs.fdata.AddDirectory(string(fname), b2i(fmtime))
			}
		}
	}

	fmt.Println("Upstream:", fs.upstream)
	fmt.Println("Remote-Directories:", fs.fdata.NumDirs())
	fmt.Println("Remote-Files:", fs.fdata.NumFiles())

	total := fs.fdata.RootDir().Size()

	fmt.Println("Remote-Size:", total, size2ui(total))

	var lfiles int64
	var ldirs int64
	var lsize int64
	var lindex int64
	index := fs.prefix[1:] + fs.fftl
	err = filepath.WalkDir(fs.prefix[1:],
		func(path string, d iofs.DirEntry, err error) error {
			if path == fs.prefix[1:] {
				return nil
			}

			if path == index {
				fi, err := d.Info()
				if err == nil {
					lindex = fi.Size()
				}
				return nil
			}

			mpath := strings.TrimPrefix(path, fs.prefix[1:])

			ent, ok := fs.fdata.Lookup(mpath)
			if !ok {
				if d.IsDir() {
					fmt.Println(" -> Cleanup-d:", path)
					// os.RemoveAll(path)
					return iofs.SkipDir
				} else {
					fmt.Println(" -> Cleanup:", path)
					// os.Remove(path)
				}
				return nil
			}
			if ent.IsDir() != d.IsDir() {
				fmt.Println(" -> Cleanup-s:", ent.IsDir(), d.IsDir(), path)
				// os.RemoveAll(path)
				if d.IsDir() {
					return iofs.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				ldirs += 1
			} else {
				lfiles += 1
				fi, err := d.Info()
				if err == nil {
					lsize += fi.Size()
				}
			}

			return nil
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to Walk (%s): %s\n", fs.prefix, err)
	}

	fmt.Println("Local-Directories:", ldirs)
	fmt.Println("Local-Files:", lfiles)
	fmt.Println("Local-Size:", lsize, size2ui(lsize))
	fmt.Println("Local-Index:", lindex, size2ui(lindex))
}

func setup_Fedora() *fedStore {
	fedora_upstream := "https://dl.fedoraproject.org/pub/fedora"
	fedora_prefix := "/Fedora/"

	fs := NewFedstore(fedora_upstream, fedora_prefix, "fullfiletimelist-fedora")
	_setup(fs)
	return fs
}

func setup_EPEL() *fedStore {
	fedora_upstream := "https://dl.fedoraproject.org/pub/epel"
	fedora_prefix := "/EPEL/"

	fs := NewFedstore(fedora_upstream, fedora_prefix, "fullfiletimelist-epel")
	_setup(fs)
	return fs
}

func setup_Fedora2nd() *fedStore {
	fedora_upstream := "https://dl.fedoraproject.org/pub/fedora-secondary"
	fedora_prefix := "/Fedora-secondary/"

	fs := NewFedstore(fedora_upstream, fedora_prefix, "fullfiletimelist-fedora-secondary")
	_setup(fs)
	return fs
}

func setup_FedoraAlt() *fedStore {
	fedora_upstream := "https://dl.fedoraproject.org/pub/alt"
	fedora_prefix := "/Fedora-alt/"

	fs := NewFedstore(fedora_upstream, fedora_prefix, "fullfiletimelist-alt")
	_setup(fs)
	return fs
}

func main() {
	var (
		fhelp    = flag.Bool("help", false, "display this message")
		fversion = flag.Bool("version", false, "display version")
		fport    = flag.Int("P", 80, `default port to use (default: 80)`)
		fpath    = flag.String("path", ".", `Root for storage`)
	)

	flag.Parse()

	if *fhelp {
		flag.Usage()
		os.Exit(0)
	}

	if *fversion {
		fmt.Println("Version:", version)
		os.Exit(0)
	}

	if *fpath != "." {
		if err := os.Chdir(*fpath); err != nil {
			fmt.Fprintf(os.Stderr, "Bad path (%s): %s\n", *fpath, err)
			os.Exit(1)
		}
	}

	// centfs := setup_CentOS()
	epelfs := setup_EPEL()
	fedfs := setup_Fedora()
	fed2fs := setup_Fedora2nd()
	fedafs := setup_FedoraAlt()

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html")

		fmt.Fprintf(w, `<html> 
		<head> <title> %s </title> </head>
		<body>
		<h1> %s </h1>
		<ul>
		<li> <a href="/stats">stats</a></li>
		<li> <a href="/CentOS/">CentOS</a></li>
		<li> <a href="/EPEL/">EPEL</a> - Updated: %s</li>
		<li> <a href="/Fedora/">Fedora</a> - Updated: %s</li>
		<li> <a href="/Fedora-secondary/">Fedora secondary arches</a> - Updated: %s</li>
		<li> <a href="/Fedora-alt/">Fedora alt</a> - Updated: %s</li>
		</ul>
		</body>
		</html>
		`, "Fedora automirror", "Fedora automirror",
			mtime2ui(epelfs.indextm.Unix()), mtime2ui(fedfs.indextm.Unix()),
			mtime2ui(fed2fs.indextm.Unix()), mtime2ui(fedafs.indextm.Unix()))
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		fmt.Fprintf(w, `{ "Version":, "%s",%s`, version, "\n")
		// fmt.Fprintf(w, `  "CentOS-Reqs":, %d,%s`, centfs.getReq(), "\n")
		// fmt.Fprintf(w, `  "CentOS-Downloads":, %d,%s`, centfs.getDwn(), "\n")
		fmt.Fprintf(w, `  "EPEL-Reqs":, %d,%s`, epelfs.getReq(), "\n")
		fmt.Fprintf(w, `  "EPEL-Downloads":, %d,%s`, epelfs.getDwn(), "\n")
		fmt.Fprintf(w, `  "Fedora-Reqs":, %d,%s`, fedfs.getReq(), "\n")
		fmt.Fprintf(w, `  "Fedora-Downloads":, %d,%s`, fedfs.getDwn(), "\n")
		fmt.Fprintf(w, `  "Fedora2nd-Reqs":, %d,%s`, fed2fs.getReq(), "\n")
		fmt.Fprintf(w, `  "Fedora2nd-Downloads":, %d,%s`, fed2fs.getDwn(), "\n")
		fmt.Fprintf(w, `  "FedoraAlt-Reqs":, %d,%s`, fedafs.getReq(), "\n")
		fmt.Fprintf(w, `  "FedoraAlt-Downloads":, %d,%s`, fedafs.getDwn(), "\n")

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		// Bytes of allocated heap objects
		fmt.Fprintf(w, `  "GC-Alloc":, %d,%s`, m.Alloc, "\n")
		// Cumulative bytes allocated for heap objects
		fmt.Fprintf(w, `  "GC-TotalAlloc":, %d,%s`, m.TotalAlloc, "\n")
		// Total bytes of memory obtained from the OS
		fmt.Fprintf(w, `  "GC-Sys":, %d,%s`, m.Sys, "\n")
		// Number of completed GC cycles
		fmt.Fprintf(w, `  "GC-Num":, %d,%s`, m.NumGC, "\n")

		fmt.Fprintf(w, `  "Uptime":, "%s" }%s`, time.Since(fedfs.beg), "\n")
	})

	// hfs := http.StripPrefix(fs.prefix, fs)
	//	http.Handle("/CentOS/", centfs)
	http.Handle(epelfs.prefix, epelfs)
	http.Handle(fedfs.prefix, fedfs)
	http.Handle(fed2fs.prefix, fed2fs)
	http.Handle(fedafs.prefix, fedafs)

	fmt.Println("Ready")
	http.ListenAndServe(":"+strconv.Itoa(*fport), nil)

}
