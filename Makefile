all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -I _include -I lsadump/include -Os -s -c lsadump/secrets.c -o _bin/lsadump_secrets.x64.o -DBOF -w -Wno-int-conversion -Wno-incompatible-pointer-types && x86_64-w64-mingw32-strip --strip-unneeded _bin/lsadump_secrets.x64.o) && echo '[+] lsadump_secrets' || echo '[!] lsadump_secrets'
	@(x86_64-w64-mingw32-gcc -I _include -I lsadump/include -Os -s -c lsadump/sam.c -o _bin/lsadump_sam.x64.o -DBOF -w -Wno-int-conversion -Wno-incompatible-pointer-types && x86_64-w64-mingw32-strip --strip-unneeded _bin/lsadump_sam.x64.o) && echo '[+] lsadump_sam' || echo '[!] lsadump_sam'
	@(x86_64-w64-mingw32-gcc -I _include -I lsadump/include -Os -s -c lsadump/cache.c -o _bin/lsadump_cache.x64.o -DBOF -w -Wno-int-conversion -Wno-incompatible-pointer-types && x86_64-w64-mingw32-strip --strip-unneeded _bin/lsadump_cache.x64.o) && echo '[+] lsadump_cache' || echo '[!] lsadump_cache'


clean:
	@(rm -rf _bin)
