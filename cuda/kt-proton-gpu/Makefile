# Host optimisation must be requested explicitly: nvcc's -O applies to device
# code, and the assembly pass is ordinary host C++ that runs 260M times.
NVCC   ?= nvcc
ARCH   ?= sm_86          # A10 / Ampere. Set for the card you have.
CFLAGS ?= -O3 -arch=$(ARCH) -Xcompiler "-O3 -fopenmp"

kt-proton-gpu: main.cu
	$(NVCC) $(CFLAGS) -o $@ $<

clean:
	rm -f kt-proton-gpu
