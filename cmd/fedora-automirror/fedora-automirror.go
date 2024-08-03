package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	roc "github.com/james-antill/rename-on-close"
)

const version = "0.1.1"

var counter int

func fnsync(upstream, fname string) (io.Closer, io.ReadSeeker, error) {
	local := false

	fmt.Println("Req:", fname)

	fi, err := os.Stat(fname)
	if err == nil { // File exists...
		resp, err := http.Head(upstream + "/" + fname)
		if err != nil {
			return nil, nil, err
		}

		fmt.Fprintln(os.Stderr, "JDBG:", "resp", resp.StatusCode, resp.ContentLength)
		if resp.StatusCode == 200 &&
			resp.ContentLength == fi.Size() {

			fmt.Fprintln(os.Stderr, "JDBG:", "mtime", fi.ModTime())
			pt, err := http.ParseTime(resp.Header.Get("Last-Modified"))
			fmt.Fprintln(os.Stderr, "JDBG:", "pt", pt)
			if err == nil && pt.Equal(fi.ModTime()) {
				local = true
			}
		}
	}

	fmt.Fprintln(os.Stdout, "JDBG:", "local", local)

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

		fmt.Fprintln(os.Stderr, "JDBG:", "resp", resp.StatusCode, resp.ContentLength)

		if resp.StatusCode != 200 {
			return nil, nil, http.ErrMissingFile
		}

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

	fmt.Fprintln(os.Stdout, "JDBG:", "got")

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
	v, err := strconv.ParseInt(string(b), 10, 0)
	if err != nil {
		return -1
	}
	return v
}

func setup(fs *fedStore, path *string) {
	if err := os.Chdir(*path); err != nil {
		fmt.Fprintf(os.Stderr, "Bad path (%s): %s\n", *path, err)
		os.Exit(1)
	}

	ioc, ior, err := fnsync(fs.upstream, "fullfiletimelist-fedora")
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
			fs.dpaths[string(fname)] = b2i(fmtime)
		}
	}
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
	counter  int
	mutex    sync.Mutex
	fpaths   map[string]fdata
	dpaths   map[string]int64
}

func NewFedstore(upstream, prefix string) *fedStore {
	var ret fedStore

	ret.upstream = upstream
	ret.prefix = prefix
	ret.beg = time.Now()
	ret.fpaths = make(map[string]fdata)
	ret.dpaths = make(map[string]int64)
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

type httpDent struct {
	name string

	mtime int64
	size  int64
}

func (fs *fedStore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	fs.incReq()

	path := strings.TrimPrefix(req.URL.Path, fs.prefix)
	fmt.Println("Path:", path)

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

		// Show a dir. listing...
		w.Header().Set("Content-Type", "text/html")

		fmt.Fprintf(w, `<html> 
		<head> <title> Path: %s </title> </head>
		<body>
		<h1> Fedora Path: %s </h1>

<table>
 <tr>
 <th>Name</th>
 <th>Last Modified</th>
 <th>Size</th>
 </tr>
 `, req.URL.Path, path)

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

			pfiles = append(pfiles, httpDent{fname, val, -1})
		}

		for key, val := range fs.fpaths {
			if !strings.HasPrefix(key, path) {
				continue
			}

			fname := key[len(path):]
			if strings.Index(fname, "/") != -1 {
				continue
			}

			pfiles = append(pfiles, httpDent{fname, val.mtime, val.size})
		}

		sort.Slice(pfiles, func(i, j int) bool {
			return strings.Compare(pfiles[i].name, pfiles[j].name) < 0
		})

		fmt.Fprintf(w, `<tr>
		<td> <a href="%s/">%s/</a> </td> <td>%s</td> <td>-</td>
		</tr> `, "..", "..", "-")

		for _, val := range pfiles {
			if val.size == -1 {
				// Print a directory...
				fmt.Fprintf(w, `<tr>
						<td> <a href="%s/">%s/</a> </td> <td>%s</td> <td>-</td>
						</tr> `, val.name, val.name, mtime2ui(val.mtime))
			} else {
				// Print a file...
				fmt.Fprintf(w, `<tr>
<td> <a href="%s">%s</a> </td> <td>%s</td> <td>%s</td>
</tr> `, val.name, val.name, mtime2ui(val.mtime), size2ui(val.size))
			}
		}

		fmt.Fprintf(w, `
		</table>
		</body>
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

	ioc, ior, err := fnsync(fs.upstream, path)
	defer ioc.Close()
	if err != nil {
		// ErrMissingFile ?
		panic(http.ErrAbortHandler)
	}

	mtime := time.Unix(int64(val.mtime), 0)
	http.ServeContent(w, req, filepath.Base(req.URL.Path), mtime, ior)
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

		fmt.Fprintf(w, `{ "Upstream": "%s",
		"Version:", %s,
		"Reqs:", %d,
		"Uptime:", %s }`, fs.upstream, version, fs.getReq(), time.Since(fs.beg))
	})

	// hfs := http.StripPrefix(fs.prefix, fs)
	fmt.Fprintln(os.Stderr, "JDBG:", "fs", fs.upstream, fs.prefix, len(fs.dpaths), len(fs.fpaths))
	http.Handle(fs.prefix, fs)

	http.ListenAndServe(":"+strconv.Itoa(*fport), nil)

}
