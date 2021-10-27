2.27:
	gcc test.c -g -o test
	patchelf --set-interpreter /home/ybw/repos_pwn/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so --set-rpath /home/ybw/repos_pwn/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 test
	echo "dir ~/.glibc/glibc-2.27/malloc" > .gdbinit
2.23:
	gcc test.c -g -o test
	patchelf --set-interpreter /home/ybw/repos_pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.27.so --set-rpath /home/ybw/repos_pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64 test
	echo "dir ~/.glibc/glibc-2.23/malloc" > .gdbinit
clean:
	tools/pwn_clean && rm .*_history core test 2>/dev/null
