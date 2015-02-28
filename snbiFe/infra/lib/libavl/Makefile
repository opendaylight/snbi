default: libavl

libavl.o: libavl.c $(HEADERS)
	    gcc -c libavl.c -o libavl.o

libavl_test.o: libavl_test.c $(HEADERS)
	    gcc -c libavl_test.c -o libavl_test.o

libavl: libavl.o libavl_test.o
	    gcc -o libavl libavl.o libavl_test.o

clean:
			-rm -f libavl.o
			-rm -f libavl_test.o
			-rm -f libavl
