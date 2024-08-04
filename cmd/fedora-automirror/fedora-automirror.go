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

	roc "github.com/james-antill/rename-on-close"
)

const version = "0.1.1"

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

func fnsync(fs *fedStore, fname string) (io.Closer, io.ReadSeeker, error) {
	upstream := fs.upstream
	local := false

	fmt.Println("Req:", fname)

	fi, err := os.Stat(fname)
	if err == nil { // File exists...
		resp, err := http.Head(upstream + "/" + fname)
		if err != nil {
			return nil, nil, err
		}

		if resp.StatusCode == 200 &&
			resp.ContentLength == fi.Size() {

			pt, err := http.ParseTime(resp.Header.Get("Last-Modified"))
			if err == nil && pt.Equal(fi.ModTime()) {
				local = true
			}
		}
	}

	if !local {
		dname := filepath.Dir(fname)
		os.MkdirAll(dname, 0755)
		nf, err := roc.Create(fname)
		if err != nil {
			return nil, nil, err
		}
		defer nf.Close()

		resp, err := http.Get(upstream + "/" + fname)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, nil, http.ErrMissingFile
		}

		fs.incDwn()
		fmt.Fprintln(os.Stdout, " -> Downloading:", resp.ContentLength, fname)

		if _, err := io.Copy(nf, resp.Body); err != nil {
			return nil, nil, err
		}
		if err := nf.CloseRename(); err != nil {
			return nil, nil, err
		}

		pt, err := http.ParseTime(resp.Header.Get("Last-Modified"))
		if err == nil {
			_ = os.Chtimes(fname, pt, pt)
		}
	}

	fo, err := os.Open(fname)
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

type fdata struct {
	mtime int64
	size  int64
}
type fedStore struct {
	upstream string
	prefix   string
	beg      time.Time

	counter   int // Number of requests
	downloads int // Number of pass through downloads
	mutex     sync.Mutex

	fpaths map[string]fdata
	dpaths map[string]fdata
}

func NewFedstore(upstream, prefix string) *fedStore {
	var ret fedStore

	ret.upstream = upstream
	ret.prefix = prefix
	ret.beg = time.Now()
	ret.fpaths = make(map[string]fdata)
	ret.dpaths = make(map[string]fdata)
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
func breadcrumpsSplit(path string) string {
	bcs := strings.Split(path, "/")

	ret := ""
	i := len(bcs) - 1
	ret = bcs[i]
	orev := "../"
	crev := orev
	for i--; i > 0; i-- {
		// Walk the path backwards...
		bc := bcs[i]
		prv := fmt.Sprintf(`<a href="%s">%s</a> / `, crev, bc)
		ret = prv + ret
		crev = crev + orev
	}

	return ret
}

func (fs *fedStore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	fs.incReq()

	path := strings.TrimPrefix(req.URL.Path, fs.prefix)
	fmt.Println("Path:", path)
	if path == "" { // See hack below...
		path = "/"
	}

	if strings.HasSuffix(path, "/") {
		path := strings.TrimRight(path, "/")
		if path == "" { // FIXME: Giant hack atm.
			path = req.URL.Path + "linux/"
			http.Redirect(w, req, path, http.StatusMovedPermanently)
			return
		}

		_, ok := fs.dpaths[path]
		if !ok {
			http.NotFound(w, req)
			return
		}

		// Show a dir. listing. Again see: https://www.datatables.net
		w.Header().Set("Content-Type", "text/html")

		fmt.Fprintf(w, `<html> 
		<head> <title> FP: %s </title> %s </head>
		<body>
		<h4> Mirror of: %s </h4>
		<h1> Fedora Path: %s </h1>

<table id="dirdata" style="compact">
 <thead>
  <tr>
   <th>Name</th>
   <th>Last Modified</th>
   <th>Size</th>
  </tr>
 </thead>
 <tbody>
 `, path, cssStyle, fs.upstream+"/"+path, breadcrumpsSplit(path))

		path = path + "/"
		pfiles := []httpDent{}
		for key, val := range fs.dpaths {
			val := val

			if !strings.HasPrefix(key, path) {
				continue
			}

			fname := key[len(path):]
			if strings.Index(fname, "/") != -1 {
				continue
			}

			pfiles = append(pfiles, httpDent{fname, val.mtime, val.size, true})
		}

		for key, val := range fs.fpaths {
			if !strings.HasPrefix(key, path) {
				continue
			}

			fname := key[len(path):]
			if strings.Index(fname, "/") != -1 {
				continue
			}

			pfiles = append(pfiles, httpDent{fname, val.mtime, val.size, false})
		}

		sort.Slice(pfiles, func(i, j int) bool {
			// rpmvercmp?
			in := s2i(pfiles[i].name)
			jn := s2i(pfiles[j].name)
			if in != -1 && jn != -1 {
				return in-jn < 0
			}
			return strings.Compare(pfiles[i].name, pfiles[j].name) < 0
		})

		fmt.Fprintf(w, `<tr>
		<td> <a href="%s/">%s/</a> </td> <td>%s</td> <td>-</td>
		</tr> `, "..", "..", "-")

		for _, val := range pfiles {
			if val.isdir {
				// Print a directory...
				fmt.Fprintf(w, `<tr>
<td> <a href="%s/">%s/</a> </td> <td>%s</td> <td>%s</td>
</tr> `, val.name, val.name, mtime2ui(val.mtime), size2ui(val.size))
			} else {
				// Print a file...
				fmt.Fprintf(w, `<tr>
<td> <a href="%s">%s</a> </td> <td>%s</td> <td>%s</td>
</tr> `, val.name, val.name, mtime2ui(val.mtime), size2ui(val.size))
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

	val, ok := fs.fpaths[path]
	if !ok {
		_, ok = fs.dpaths[path]
		if !ok {
			http.NotFound(w, req)
			return
		}

		path = req.URL.Path + "/"
		http.Redirect(w, req, path, http.StatusMovedPermanently)
		return
	}

	ioc, ior, err := fnsync(fs, path)
	defer ioc.Close()
	if err != nil {
		// ErrMissingFile ?
		panic(http.ErrAbortHandler)
	}

	mtime := time.Unix(int64(val.mtime), 0)
	fmt.Println(" -> Serving:", path)
	http.ServeContent(w, req, filepath.Base(path), mtime, ior)
	fmt.Println(" -> Done:", path)
}

func setup(fs *fedStore, path *string) {
	if err := os.Chdir(*path); err != nil {
		fmt.Fprintf(os.Stderr, "Bad path (%s): %s\n", *path, err)
		os.Exit(1)
	}

	ioc, ior, err := fnsync(fs, "fullfiletimelist-fedora")
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
			fs.fpaths[string(fname)] = fdata{b2i(fmtime), b2i(fsize)}
		case "d":
			fs.dpaths[string(fname)] = fdata{b2i(fmtime), -1}
		}
	}

	fmt.Println("Remote-Directories:", len(fs.dpaths))
	fmt.Println("Remote-Files:", len(fs.fpaths))

	var total int64
	for path, val := range fs.fpaths {
		total += val.size

		for dpath := filepath.Dir(path); dpath != "."; dpath = filepath.Dir(dpath) {
			t := fs.dpaths[dpath]
			t.size += val.size
			fs.dpaths[dpath] = t
		}
	}

	fmt.Println("Remote-Size:", total, size2ui(total))

	var lfiles int64
	var ldirs int64
	var lsize int64
	var lindex int64
	err = filepath.WalkDir(".",
		func(path string, d iofs.DirEntry, err error) error {
			if path == "." {
				return nil
			}
			if path == "fullfiletimelist-fedora" {
				fi, err := d.Info()
				if err == nil {
					lindex = fi.Size()
				}
				return nil
			}

			path = strings.TrimPrefix(path, "./")

			if d.IsDir() {
				_, ok := fs.dpaths[path]
				if !ok {
					fmt.Println(" -> Cleanup-d:", path)
					os.RemoveAll(path)
					return iofs.SkipDir
				}

				ldirs += 1
			} else {
				_, ok := fs.fpaths[path]
				if !ok {
					fmt.Println(" -> Cleanup:", path)
					os.Remove(path)
					return nil
				}

				lfiles += 1
				fi, err := d.Info()
				if err == nil {
					lsize += fi.Size()
				}
			}

			return nil
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to Walk (%s): %s\n", *path, err)
	}

	fmt.Println("Local-Directories:", ldirs)
	fmt.Println("Local-Files:", lfiles)
	fmt.Println("Local-Size:", lsize, size2ui(lsize))
	fmt.Println("Local-Index:", lindex, size2ui(lindex))
}

func main() {
	var (
		fhelp     = flag.Bool("help", false, "display this message")
		fversion  = flag.Bool("version", false, "display version")
		fupstream = flag.String("upstream", "https://dl.fedoraproject.org/pub/fedora", `upstream URL`)
		fprefix   = flag.String("prefix", "/Fedora", `prefix for Fedora`)
		fport     = flag.Int("P", 80, `default port to use (default: 80)`)
		fpath     = flag.String("path", "Fedora", `prefix for Fedora`)
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

	if (*fprefix)[0] != '/' {
		*fprefix = "/" + *fprefix
	}
	if (*fprefix)[len(*fprefix)-1] != '/' {
		*fprefix = *fprefix + "/"
	}

	if strings.Index(*fprefix, "//") != -1 {
		fmt.Fprintln(os.Stderr, "Bad prefix (contains //):", *fprefix)
		os.Exit(1)
	}

	fs := NewFedstore(*fupstream, *fprefix)
	setup(fs, fpath)

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html")

		fmt.Fprintf(w, `<html> 
		<head> <title> %s </title> </head>
		<body>
		<h1> %s </h1>
		<ul>
		<li> <a href="/stats">stats</a></li>
		<li> <a href="%s">Fedora</a></li>
		</ul>
		</body>
		</html>
		`, "Fedora automirror", "Fedora automirror", fs.prefix)
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		fmt.Fprintf(w, `{ "Version":, "%s",%s`, version, "\n")
		fmt.Fprintf(w, `  "Reqs":, %d,%s`, fs.getReq(), "\n")
		fmt.Fprintf(w, `  "Downloads":, %d,%s`, fs.getDwn(), "\n")

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

		fmt.Fprintf(w, `  "Uptime":, "%s" }%s`, time.Since(fs.beg), "\n")
	})

	// hfs := http.StripPrefix(fs.prefix, fs)
	http.Handle(fs.prefix, fs)

	fmt.Println("Ready")
	http.ListenAndServe(":"+strconv.Itoa(*fport), nil)

}
