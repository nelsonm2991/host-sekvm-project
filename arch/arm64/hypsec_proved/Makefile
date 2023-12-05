#
# Makefile for host Kernel running with stage 2 translation
#
ccflags-y := -fno-stack-protector -ffreestanding

obj-y += el1.o
obj-y += el2.o
obj-y += s2-setup.o
obj-y += AbstractMachine.o
obj-y += MemRegion.o
obj-y += PageIndex.o
obj-y += PageManager.o
obj-y += PTAlloc.o
obj-y += PTWalk.o
obj-y += NPTWalk.o
obj-y += NPTOps.o
obj-y += MemManagerAux.o
obj-y += MemManager.o
obj-y += MemoryOps.o
obj-y += VMPower.o
obj-y += BootCore.o
obj-y += BootOps.o
obj-y += BootAux.o
obj-y += Helper.o
obj-y += VCPUOpsAux.o
obj-y += VCPUOps.o
#obj-y += mmap.o
#obj-y += sysreg-sr.o
obj-y += sysreg-sr-opt.o
#obj-y += hacl-20/
obj-y += MmioOps.o
obj-y += MmioOpsAux.o
obj-y += MmioCore.o
obj-y += MmioCoreAux.o
obj-y += MmioRaw.o
obj-y += MemHandler.o
obj-y += SmmuPTAlloc.o
obj-y += SmmuPTOps.o
obj-y += SmmuPTWalk.o
obj-y += SmmuSPTWalk.o
#dpm
obj-y += DPM.o
