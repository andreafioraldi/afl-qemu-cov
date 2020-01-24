all: afl-qemu-cov afl-qemu-cov-tracer

afl-qemu-cov: afl-qemu-cov.c include/*.h
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

afl-qemu-cov-tracer: patches/*
	./build_qemu.sh

clean:
	rm -rf qemu-* afl-qemu-cov afl-qemu-cov-tracer
