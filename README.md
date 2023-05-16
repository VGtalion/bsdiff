# bsdiff 4.3

This is based on the source code of bsdiff and bspatch, from daemonology : https://www.daemonology.net/bsdiff/

The folloowing debian patches have been applyed :
- 10-no-bsd-make.patch
- 20-CVE-2014-9862.patch
- 30-bug-632585-mmap-src-file-instead-of-malloc-read-it.patch
- 31-bug-632585-mmap-dst-file-instead-of-malloc-read-it.patch
- 32-bug-632585-use-int32_t-instead-off_t-for-file-size.patch
- 33-CVE-2020-14315.patch

Finally I fixed the Bug#975055: "bsdiff: make bspatch a little less memory hungry".
