src := test.cxx websocmm.cxx wmm_types.cxx

CXXFLAGS := -u -g -o

testmm : $(src)
	$(CXX) testmm $(src) -I/usr/local/openssl/include/ -L/usr/local/openssl/lib -lcrypto -lssl

.PHONY:clean
clean:
	rm -f *.o
