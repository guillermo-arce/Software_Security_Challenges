## Fuzzing Challenge

### Objective: Find Heartbleed vulnerability 
For that purpose we will be using ASAN (Address Sanitizer) and AFL (American Fuzzy Lop).

→ **ASAN**: Open source programming tool by Google that detects memory corruption bugs such as buffer overflows or accesses to 
	 a dangling pointer (use-after-free). AddressSanitizer is based on compiler instrumentation and directly-mapped shadow memory. 

→ **AFL**: Free software fuzzer that employs genetic algorithms in order to efficiently increase code coverage of the test cases.

### Procedure
After a process of installation and make everything work, the procedure to follow was the next one:

1º Compile and build OpenSSL enabling the Address Sanitizer:  
```
	$ AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ ./config -d –g
	$ make
```
2º Create a fake certificate in order to simulate a client:
```
	$ openssl req -x509 -newkey rsa:512 -keyout server.key -out server.pem -days 9999 -nodes -subj /CN=a/
```
3º Compile the handshake to test enabling ASAN:
```
	$ AFL_USE_ASAN=1 AFL/afl-clang-fast++ handshake.cc -o handshake openssl-1.0.1f/libssl.a openssl-1.0.1f/libcrypto.a -I openssl-1.0.1f/include -ldl
```
The handshake.cc file is a c++ program:
```
  // Copyright 2016 Google Inc. All Rights Reserved.
  // Licensed under the Apache License, Version 2.0 (the "License");
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <assert.h>
  #include <stdint.h>
  #include <stddef.h>
  #include <unistd.h>

  #ifndef CERT_PATH
  # define CERT_PATH
  #endif

  SSL_CTX *Init() {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX *sctx;
    assert (sctx = SSL_CTX_new(TLSv1_method()));
    /* These two file were created with this command:
        openssl req -x509 -newkey rsa:512 -keyout server.key \
       -out server.pem -days 9999 -nodes -subj /CN=a/
    */
    assert(SSL_CTX_use_certificate_file(sctx, "server.pem",
                            SSL_FILETYPE_PEM));
    assert(SSL_CTX_use_PrivateKey_file(sctx, "server.key",
                           SSL_FILETYPE_PEM));
    return sctx;
  }

  int main() {
    static SSL_CTX *sctx = Init();
    SSL *server = SSL_new(sctx);
    BIO *sinbio = BIO_new(BIO_s_mem());
    BIO *soutbio = BIO_new(BIO_s_mem());
    SSL_set_bio(server, sinbio, soutbio);
    SSL_set_accept_state(server);


    #ifdef __AFL_HAVE_MANUAL_CONTROL
      __AFL_INIT();
    #endif

    uint8_t data[100] = {0};
    size_t size = read(STDIN_FILENO, data, 100);
    if (size == -1) {
      printf("Failed to read from stdin\n");
      return(-1);
    }

    BIO_write(sinbio, data, size);

    SSL_do_handshake(server);
    SSL_free(server);
    return 0;
  }
```
4º Create an initial input for the fuzzer in order to then apply the genetic algorithm on it (and create more test cases):
	
For that purpose, an external project from GitHub has been used → https://github.com/hannob/selftls
  
The input for the fuzz testing will be an initial packet from the handshake generated from that project.
  
5º Start the test with the program to test (handshake), the input (initial packet in folder "in") and an output folder for the results:
```
  $ afl-fuzz -i in -o out -m none -t 5000 ./handshake
```
After some time, the testing situation looks like this:
```

                     american fuzzy lop 2.56b (handshake)

┌─ process timing ─────────────────────────────────────┬─ overall results ─────┐
│        run time : 0 days, 0 hrs, 19 min, 43 sec      │  cycles done : 2      │
│   last new path : 0 days, 0 hrs, 0 min, 3 sec        │  total paths : 39     │
│ last uniq crash : 0 days, 0 hrs, 17 min, 24 sec      │ uniq crashes : 1      │
│  last uniq hang : none seen yet                      │   uniq hangs : 0      │
├─ cycle progress ────────────────────┬─ map coverage ─┴───────────────────────┤
│  now processing : 36 (92.31%)       │    map density : 4.76% / 5.32%         │
│ paths timed out : 0 (0.00%)         │ count coverage : 1.11 bits/tuple       │
├─ stage progress ────────────────────┼─ findings in depth ────────────────────┤
│  now trying : havoc                 │ favored paths : 27 (69.23%)            │
│ stage execs : 468/4096 (11.43%)     │  new edges on : 32 (82.05%)            │
│ total execs : 99.2k                 │ total crashes : 306 (1 unique)         │
│  exec speed : 73.46/sec (slow!)     │  total tmouts : 0 (0 unique)           │
├─ fuzzing strategy yields ───────────┴───────────────┬─ path geometry ────────┤
│   bit flips : 11/2272, 5/2241, 3/2179               │    levels : 7          │
│  byte flips : 0/284, 0/253, 0/193                   │   pending : 9          │
│ arithmetics : 4/15.9k, 0/14.7k, 0/4104              │  pend fav : 1          │
│  known ints : 1/963, 1/4727, 3/7335                 │ own finds : 38         │
│  dictionary : 0/0, 0/0, 0/12                        │  imported : n/a        │
│       havoc : 6/39.0k, 4/4176                       │ stability : 100.00%    │
│        trim : 46.20%/63, 0.00%                      ├────────────────────────┘
└─────────────────────────────────────────────────────┘          [cpu001:130%]
```

As we can see, a crash has appeared. Lets see what it is about.

6º Now that we have detected a crash, we just need to execute the input that provoked the crash (which is in out/crashes/..) into our program (handshake)
to get the error.
```
	$ ./handshake < out/crashes/id\:000000\,sig\:06\,src\:000004\,op\:arith8\,pos\:0\,val\:+2
```
And the output is: 
```
==45787==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x629000009748 at pc 0x0000004369e7 bp 0x7ffcca1551f0 sp 0x7ffcca1549b0
READ of size 48830 at 0x629000009748 thread T0
    #0 0x4369e6 in memcpy (/home/kali/Desktop/Challenges/Fuzzing/files/handshake+0x4369e6)
    #1 0x4d63f6 in tls1_process_heartbeat /home/kali/Desktop/Challenges/Fuzzing/files/openssl-1.0.1f/ssl/t1_lib.c:2586:3
    #2 0x555c3c in ssl3_read_bytes /home/kali/Desktop/Challenges/Fuzzing/files/openssl-1.0.1f/ssl/s3_pkt.c:1092:4
    #3 0x5582f9 in ssl3_get_message /home/kali/Desktop/Challenges/Fuzzing/files/openssl-1.0.1f/ssl/s3_both.c:457:7
    #4 0x51f508 in ssl3_get_client_hello /home/kali/Desktop/Challenges/Fuzzing/files/openssl-1.0.1f/ssl/s3_srvr.c:941:4
    #5 0x52f8d3 in ssl3_accept /home/kali/Desktop/Challenges/Fuzzing/files/openssl-1.0.1f/ssl/s3_srvr.c:357:9
    #6 0x4c9e7c in main /home/kali/Desktop/Challenges/Fuzzing/files/handshake.cc:54:3
    #7 0x7f6855c91e0a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x26e0a)
    #8 0x41fa69 in _start (/home/kali/Desktop/Challenges/Fuzzing/files/handshake+0x41fa69)

0x629000009748 is located 0 bytes to the right of 17736-byte region [0x629000005200,0x629000009748)
allocated by thread T0 here:
    #0 0x49796d in malloc (/home/kali/Desktop/Challenges/Fuzzing/files/handshake+0x49796d)
    #1 0x58b502 in CRYPTO_malloc /home/kali/Desktop/Challenges/Fuzzing/files/openssl-1.0.1f/crypto/mem.c:308:8

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/kali/Desktop/Challenges/Fuzzing/files/handshake+0x4369e6) in memcpy
Shadow bytes around the buggy address:
  0x0c527fff9290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c527fff92a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c527fff92b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c527fff92c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c527fff92d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c527fff92e0: 00 00 00 00 00 00 00 00 00[fa]fa fa fa fa fa fa
  0x0c527fff92f0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c527fff9300: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c527fff9310: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c527fff9320: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c527fff9330: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==45787==ABORTING
```
	
As we can see, the ASAN has correctly detected the heap buffer overflow of a READ of 48830 bytes 
provoked by the fuzzer! → We have found HEARTBLEED vulnerability on OpenSSL.
