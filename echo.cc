#include <fstream>
#include <iostream>
#include <random>
#include <string>

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <asm/msr-index.h>
#include <asm/prctl.h>
#include <fcntl.h>
#include <immintrin.h>
#include <linux/kvm.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "FileDescriptor.hpp"

#define KVM_MSR_ENTRY(_index, _data)                                           \
  (struct kvm_msr_entry) { .index = _index, .data = _data }

static int kvm_check_extension(FileDescriptor& kvm_handle, int capability) {
  return kvm_handle.ioctl(KVM_CHECK_EXTENSION, capability);
}

static int kvm_recommended_vcpus(FileDescriptor& kvm_handle) {
  int ret = kvm_check_extension(kvm_handle, KVM_CAP_NR_VCPUS);
  return ret ? ret : 4;
}

static int kvm_max_vcpus(FileDescriptor& kvm_handle) {
  int ret = kvm_check_extension(kvm_handle, KVM_CAP_MAX_VCPUS);
  return ret ? ret : kvm_recommended_vcpus(kvm_handle);
}

static int check_extension_vm = 0;
static int kvm_check_extension_vm(FileDescriptor& kvm_handle,
                                  FileDescriptor& vm_handle, int capability) {
  if (check_extension_vm) {
    return vm_handle.ioctl(KVM_CHECK_EXTENSION, capability);
  } else {
    return kvm_handle.ioctl(KVM_CHECK_EXTENSION, capability);
  }
}
static void print_dtable(const char* name, struct kvm_dtable* dtable) {
  printf(" %s                 %016" PRIx64 "  %08hx\n", name,
         (uint64_t)dtable->base, (uint16_t)dtable->limit);
}

static void print_segment(const char* name, struct kvm_segment* seg) {
  printf(" %s       %04hx      %016" PRIx64
         "  %08x  %02hhx    %x %x   %x  %x %x %x %x\n",
         name, (uint16_t)seg->selector, (uint64_t)seg->base,
         (uint32_t)seg->limit, (uint8_t)seg->type, seg->present, seg->dpl,
         seg->db, seg->s, seg->l, seg->g, seg->avl);
}

static void print_registers(FileDescriptor& vcpu_handle) {
  unsigned long cr0, cr2, cr3;
  unsigned long cr4, cr8;
  unsigned long rax, rbx, rcx;
  unsigned long rdx, rsi, rdi;
  unsigned long rbp, r8, r9;
  unsigned long r10, r11, r12;
  unsigned long r13, r14, r15;
  unsigned long rip, rsp;
  struct kvm_sregs sregs;
  unsigned long rflags;
  struct kvm_regs regs;
  int i;

  struct kvm_mp_state state;
  if (vcpu_handle.ioctl(KVM_GET_MP_STATE, &state) < 0) {
    fprintf(stderr, "KVM_GET_MP_STATE failed: %s\n", strerror(errno));
    exit(-1);
  }

  switch (state.mp_state) {
  case KVM_MP_STATE_RUNNABLE:
    printf("State: RUNNABLE\n");
    break;
  case KVM_MP_STATE_UNINITIALIZED:
    printf("State: UNINITIALIZED\n");
    break;
  case KVM_MP_STATE_INIT_RECEIVED:
    printf("State: INIT_RECEIVED\n");
    break;
  case KVM_MP_STATE_HALTED:
    printf("State: HALTED\n");
    break;
  case KVM_MP_STATE_SIPI_RECEIVED:
    printf("State: SIPI_RECEIVED\n");
    break;
  case KVM_MP_STATE_STOPPED:
    printf("State: STOPPED\n");
    break;
  case KVM_MP_STATE_CHECK_STOP:
    printf("State: CHECK_STOP\n");
    break;
  case KVM_MP_STATE_OPERATING:
    printf("State: OPERATING\n");
    break;
  case KVM_MP_STATE_LOAD:
    printf("State: STATE_LOAD\n");
    break;
  }

  if (vcpu_handle.ioctl(KVM_GET_REGS, &regs) < 0) {
    fprintf(stderr, "KVM_GET_REGS failed: %s\n", strerror(errno));
    exit(-1);
  }

  rflags = regs.rflags;

  rip = regs.rip;
  rsp = regs.rsp;
  rax = regs.rax;
  rbx = regs.rbx;
  rcx = regs.rcx;
  rdx = regs.rdx;
  rsi = regs.rsi;
  rdi = regs.rdi;
  rbp = regs.rbp;
  r8 = regs.r8;
  r9 = regs.r9;
  r10 = regs.r10;
  r11 = regs.r11;
  r12 = regs.r12;
  r13 = regs.r13;
  r14 = regs.r14;
  r15 = regs.r15;

  printf("\n Registers:\n");
  printf(" ----------\n");
  printf(" rip: %016lx   rsp: %016lx flags: %016lx\n", rip, rsp, rflags);
  printf(" rax: %016lx   rbx: %016lx   rcx: %016lx\n", rax, rbx, rcx);
  printf(" rdx: %016lx   rsi: %016lx   rdi: %016lx\n", rdx, rsi, rdi);
  printf(" rbp: %016lx    r8: %016lx    r9: %016lx\n", rbp, r8, r9);
  printf(" r10: %016lx   r11: %016lx   r12: %016lx\n", r10, r11, r12);
  printf(" r13: %016lx   r14: %016lx   r15: %016lx\n", r13, r14, r15);

  if (vcpu_handle.ioctl(KVM_GET_SREGS, &sregs) < 0) {
    fprintf(stderr, "KVM_GET_REGS failed");
    exit(-1);
  }

  cr0 = sregs.cr0;
  cr2 = sregs.cr2;
  cr3 = sregs.cr3;
  cr4 = sregs.cr4;
  cr8 = sregs.cr8;

  printf(" cr0: %016lx   cr2: %016lx   cr3: %016lx\n", cr0, cr2, cr3);
  printf(" cr4: %016lx   cr8: %016lx\n", cr4, cr8);
  printf("\n Segment registers:\n");
  printf(" ------------------\n");
  printf(" register  selector  base              limit     type  p dpl db s l "
         "g avl\n");
  print_segment("cs ", &sregs.cs);
  print_segment("ss ", &sregs.ss);
  print_segment("ds ", &sregs.ds);
  print_segment("es ", &sregs.es);
  print_segment("fs ", &sregs.fs);
  print_segment("gs ", &sregs.gs);
  print_segment("tr ", &sregs.tr);
  print_segment("ldt", &sregs.ldt);
  print_dtable("gdt", &sregs.gdt);
  print_dtable("idt", &sregs.idt);

  printf("\n APIC:\n");
  printf(" -----\n");
  printf(" efer: %016" PRIx64 "  apic base: %016" PRIx64 "\n",
         (uint64_t)sregs.efer, (uint64_t)sregs.apic_base);

  printf("\n Interrupt bitmap:\n");
  printf(" -----------------\n");
  for (i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
    printf(" %016" PRIx64, (uint64_t)sregs.interrupt_bitmap[i]);
  printf("\n");
}

static void map_memory(FileDescriptor& vm_handle, uint64_t phys_addr,
                       size_t size, uint64_t userspace_addr,
                       bool readonly = false) {
  static uint32_t slot = 0;
  struct kvm_userspace_memory_region region;
  region.slot = slot++;
  region.flags = readonly ? KVM_MEM_READONLY : 0;
  region.guest_phys_addr = phys_addr;
  region.memory_size = size;
  region.userspace_addr = userspace_addr;
  if (vm_handle.ioctl(KVM_SET_USER_MEMORY_REGION, &region)) {
    fprintf(stderr, "ioctl(KVM_SET_USER_MEMORY_REGION) failed: %s\n",
            strerror(errno));
    exit(-1);
  }
}

static void identity_map(FileDescriptor& vm_handle) {
  std::ifstream fp{"/proc/self/maps"};

  for (std::string line; std::getline(fp, line);) {
    uint64_t begin;
    uint64_t end;
    char permissions[5];
    if (sscanf(line.c_str(), "%" SCNx64 "-%" SCNx64 " %5s", &begin, &end,
               permissions) != 3) {
      fprintf(stderr, "Failed to parse map\n");
      exit(-1);
    }
    if (end < (1 << 30)) {
      std::cout << line << std::endl;
      map_memory(vm_handle, begin, end - begin, begin, permissions[1] != 'w');
    }
  }
}

static void handle_syscall(FileDescriptor& vcpu_handle) {
  struct kvm_regs regs;
  if (vcpu_handle.ioctl(KVM_GET_REGS, &regs) < 0) {
    fprintf(stderr, "KVM_GET_REGS failed: %s\n", strerror(errno));
    exit(-1);
  }
  register uint64_t rax asm("rax") = regs.rax;
  register uint64_t rdi asm("rdi") = regs.rdi;
  register uint64_t rsi asm("rsi") = regs.rsi;
  register uint64_t rdx asm("rdx") = regs.rdx;
  register uint64_t r8 asm("r8") = regs.r8;
  register uint64_t r9 asm("r9") = regs.r9;
  register uint64_t r10 asm("r10") = regs.r10;

  asm volatile("syscall"
               : "+a"(rax)
               : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r8), "r"(r9), "r"(r10)
               : "rcx", "r11");
  regs.rax = rax;
  if (vcpu_handle.ioctl(KVM_SET_REGS, &regs) < 0) {
    fprintf(stderr, "KVM_SET_REGS failed: %s\n", strerror(errno));
    exit(-1);
  }
}

alignas(4096) uint64_t pdpte[256] = {0x83};

alignas(4096) uint64_t pml4[256] = {(uint64_t)pdpte | 0x3};

alignas(4096) uint64_t gdt[256] = {0, 0x0020980000000000, 0x0000900000000000};

extern "C" void vm_entry();
extern "C" void syscall_entry();
extern "C" int arch_prctl(int code, unsigned long* addr);

int main() {
  printf("%lx\n", KVM_SET_MEMORY_REGION);
  auto kvm_handle = FileDescriptor::open("/dev/kvm", O_RDWR);

  int version = kvm_handle.ioctl(KVM_GET_API_VERSION, 0);
  if (version != 12) {
    if (version == -1) {
      fprintf(stderr, "Failed to get KVM version: %s\n", strerror(errno));
    } else {
      fprintf(stderr, "KVM version is not 12\n");
    }
    return -1;
  }

  int recommended_vcpus = kvm_recommended_vcpus(kvm_handle);
  printf("Recommended vcpu limit: %d\n", recommended_vcpus);

  int max_vcpus = kvm_max_vcpus(kvm_handle);
  printf("Max vcpu limit: %d\n", max_vcpus);

  check_extension_vm =
      kvm_handle.ioctl(KVM_CHECK_EXTENSION, KVM_CAP_CHECK_EXTENSION_VM);

  int vm_handle_i = kvm_handle.ioctl(KVM_CREATE_VM, 0);
  if (vm_handle_i < 0) {
    fprintf(stderr, "ioctl(KVM_CREATE_VM) failed: %s\n", strerror(vm_handle_i));
    return -1;
  }
  FileDescriptor vm_handle{vm_handle_i};

  int kvm_cap_user_mem =
      kvm_check_extension_vm(kvm_handle, vm_handle, KVM_CAP_USER_MEMORY);
  printf("VM supports user memory: %d\n", kvm_cap_user_mem);

  int kvm_cap_sync_mmu =
      kvm_check_extension_vm(kvm_handle, vm_handle, KVM_CAP_SYNC_MMU);
  printf("VM supports synchronized MMU: %d\n", kvm_cap_sync_mmu);

  auto size = 2 * (1 << 20);

  auto mem =
      mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "mmap failed: %s\n", strerror(errno));
    return -1;
  }
  map_memory(vm_handle, 0, size, (uint64_t)mem);
  // ((uint8_t *)mem)[0x100000] = 0xe4;
  // ((uint8_t *)mem)[0x100001] = 0x01;

  identity_map(vm_handle);

  // if (vm_handle.ioctl(KVM_SET_TSS_ADDR, 0xfffbd000)) {
  //   fprintf(stderr, "ioctl(KVM_SET_TSS_ADDR) falied: %s\n", strerror(errno));
  //   return -1;
  // }

  // struct kvm_pit_config config;
  // config.flags = 0;

  // if (vm_handle.ioctl(KVM_CREATE_PIT2, &config)) {
  //   fprintf(stderr, "ioctl(KVM_CREATE_PIT2) failed: %s\n", strerror(errno));
  //   return -1;
  // }

  // if (vm_handle.ioctl(KVM_CREATE_IRQCHIP)) {
  //   fprintf(stderr, "ioctl(KVM_CREATE_IRQCHIP) failed: %s\n",
  //   strerror(errno));
  //   return -1;
  // }

  int vcpu_handle_i = vm_handle.ioctl(KVM_CREATE_VCPU, 0);
  if (vcpu_handle_i < 0) {
    fprintf(stderr, "ioctl(KVM_CREATE_VCPU) failed: %s\n", strerror(errno));
    return -1;
  }
  FileDescriptor vcpu_handle{vcpu_handle_i};

  int mmap_size = kvm_handle.ioctl(KVM_GET_VCPU_MMAP_SIZE, 0);
  if (mmap_size < 0) {
    fprintf(stderr, "ioctl(KVM_GET_VCPU_MMAP_SIZE) failed: %s\n",
            strerror(errno));
    return -1;
  }

  struct kvm_run* kvm_run =
      (struct kvm_run*)mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                            vcpu_handle.get(), 0);
  if (kvm_run == MAP_FAILED) {
    fprintf(stderr, "Failed to mmap vcpu state: %s\n", strerror(errno));
    return -1;
  }

  const constexpr size_t MAX_KVM_CPUID_ENTRIES = 100;
  struct kvm_cpuid2* kvm_cpuid;
  kvm_cpuid = (struct kvm_cpuid2*)calloc(
      1,
      sizeof(*kvm_cpuid) + MAX_KVM_CPUID_ENTRIES * sizeof(*kvm_cpuid->entries));
  kvm_cpuid->nent = MAX_KVM_CPUID_ENTRIES;
  if (kvm_handle.ioctl(KVM_GET_SUPPORTED_CPUID, kvm_cpuid)) {
    fprintf(stderr, "ioctl(KVM_GET_SUPPORTED_CPUID) failed: %s\n",
            strerror(errno));
    return -1;
  }

  // unsigned int signature[3];
  // for (auto i = 0u; i < kvm_cpuid->nent; ++i) {
  //   auto entry = &kvm_cpuid->entries[i];

  //   switch (entry->function) {
  //   case 0:
  //     // memcpy(signature, "ECHOECHOECHO", 12);
  //     // entry->ebx = signature[0];
  //     // entry->ecx = signature[1];
  //     // entry->edx = signature[2];
  //     // break;
  //   case 1:
  //     // if (entry->index == 0)
  //     //   entry->ecx |= (1 << 31);
  //     break;
  //   case 6:
  //     // entry->ecx = entry->ecx & ~(1 << 3);
  //     break;
  //   case 10: {
  //     // union cpuid10_eax {
  //     //   struct {
  //     //     unsigned int version_id : 8;
  //     //     unsigned int num_counters : 8;
  //     //     unsigned int bit_width : 8;
  //     //     unsigned int mask_length : 8;
  //     //   } split;
  //     //   unsigned int full;
  //     // } eax;

  //     // /*
  //     //  * If the host has perf system running,
  //     //  * but no architectural events available
  //     //  * through kvm pmu -- disable perf support,
  //     //  * thus guest won't even try to access msr
  //     //  * registers.
  //     //  */
  //     // if (entry->eax) {
  //     //   eax.full = entry->eax;
  //     //   if (eax.split.version_id != 2 || !eax.split.num_counters)
  //     //     entry->eax = 0;
  //     // }
  //     break;
  //   }
  //   default:
  //     /* Keep the CPUID function as -is */
  //     break;
  //   };
  // }

  if (vcpu_handle.ioctl(KVM_SET_CPUID2, kvm_cpuid) < 0) {
    fprintf(stderr, "ioctl(KVM_SET_CPUID2) failed: %s\n", strerror(errno));
    return -1;
  }

  free(kvm_cpuid);

  // struct kvm_msrs* msrs = (struct kvm_msrs*)calloc(
  //     1, sizeof(*msrs) + (sizeof(struct kvm_msr_entry) * 100));
  // size_t ndx = 0;
  // msrs->entries[ndx].index = MSR_IA32_SYSENTER_CS;
  // msrs->entries[ndx++].data = 0;
  // msrs->entries[ndx].index = MSR_IA32_SYSENTER_ESP;
  // msrs->entries[ndx++].data = 0;
  // msrs->entries[ndx].index = MSR_IA32_SYSENTER_EIP;
  // msrs->entries[ndx++].data = 0;
  // msrs->entries[ndx].index = MSR_STAR;
  // msrs->entries[ndx++].data = 0x8ULL << 32;
  // msrs->entries[ndx].index = MSR_CSTAR;
  // msrs->entries[ndx++].data = 0;
  // msrs->entries[ndx].index = MSR_KERNEL_GS_BASE;
  // msrs->entries[ndx++].data = 0;
  // msrs->entries[ndx].index = MSR_SYSCALL_MASK;
  // msrs->entries[ndx++].data = 0;
  // msrs->entries[ndx].index = MSR_LS TAR;
  // msrs->entries[ndx++].data = (uint64_t)syscall_entry;
  // msrs->entries[ndx].index = MSR_IA32_TSC;
  // msrs->entries[ndx++].data = 0;
  // msrs->entries[ndx].index = MSR_IA32_MISC_ENABLE;
  // msrs->entries[ndx++].data = MSR_IA32_MISC_ENABLE_FAST_STRING;

  // msrs->nmsrs = ndx;

  struct kvm_sregs sregs;
  if (vcpu_handle.ioctl(KVM_GET_SREGS, &sregs)) {
    fprintf(stderr, "ioctl(KVM_GET_SREGS) failed: %s\n", strerror(errno));
    return -1;
  }

  sregs.cs.base = 0x0;
  sregs.cs.limit = 0xffffffff;
  sregs.cs.selector = 0x8;
  sregs.cs.type = 0xb;
  sregs.cs.present = 1;
  sregs.cs.dpl = 0;
  sregs.cs.db = 0;
  sregs.cs.s = 1;
  sregs.cs.l = 1;
  //sregs.cs.l = 0;
  sregs.cs.g = 1;
  sregs.cs.avl = 0;

  sregs.ss.base = 0x0;
  sregs.ss.limit = 0xffffffff;
  sregs.ss.selector = 0;
  sregs.ss.type = 0;
  sregs.ss.present = 0;
  sregs.ss.dpl = 0;
  sregs.ss.db = 1;
  sregs.ss.s = 0;
  sregs.ss.l = 0;
  sregs.ss.g = 1;
  sregs.ss.avl = 0;

  sregs.ds.base = 0x0;
  sregs.ds.limit = 0xffffffff;
  sregs.ds.selector = 0;
  sregs.ds.type = 0;
  sregs.ds.present = 0;
  sregs.ds.dpl = 0;
  sregs.ds.db = 1;
  sregs.ds.s = 0;
  sregs.ds.l = 0;
  sregs.ds.g = 1;
  sregs.ds.avl = 0;

  sregs.es.base = 0x0;
  sregs.es.limit = 0xffffffff;
  sregs.es.selector = 0;
  sregs.es.type = 0;
  sregs.es.present = 0;
  sregs.es.dpl = 0;
  sregs.es.db = 1;
  sregs.es.s = 0;
  sregs.es.l = 0;
  sregs.es.g = 1;
  sregs.es.avl = 0;

  uint64_t fs_base;
  arch_prctl(ARCH_GET_FS, &fs_base);

  sregs.fs.base = fs_base;
  sregs.fs.base = 0x0;
  sregs.fs.limit = 0xffffffff;
  sregs.fs.selector = 0;
  sregs.fs.type = 0;
  sregs.fs.present = 0;
  sregs.fs.dpl = 0;
  sregs.fs.db = 1;
  sregs.fs.s = 0;
  sregs.fs.l = 0;
  sregs.fs.g = 1;
  sregs.fs.avl = 0;

  sregs.gs.base = 0x0;
  sregs.gs.limit = 0xffffffff;
  sregs.gs.selector = 0;
  sregs.gs.type = 0;
  sregs.gs.present = 0;
  sregs.gs.dpl = 0;
  sregs.gs.db = 1;
  sregs.gs.s = 0;
  sregs.gs.l = 0;
  sregs.gs.g = 1;
  sregs.gs.avl = 0;

  sregs.ldt.present = 0;
  sregs.gdt.base = (uint64_t)gdt;
  sregs.gdt.limit = 23;

  sregs.cr0 = 0x80050033;
  //sregs.cr0 = 0x50033;
  sregs.cr3 = (uint64_t)pml4;
  sregs.cr4 = 0x1406b0;
  sregs.efer = 0xd01;

  if (vcpu_handle.ioctl(KVM_SET_SREGS, &sregs)) {
    fprintf(stderr, "ioctl(KVM_SET_SREGS) failed: %s\n", strerror(errno));
    return -1;
  }

  // printf("vm_entry: %#" PRIxPTR "\n", (uintptr_t)vm_entry);
  // struct kvm_translation translation;
  // translation.linear_address = (uintptr_t)vm_entry;
  // if (vcpu_handle.ioctl(KVM_TRANSLATE, &translation)) {
  //   fprintf(stderr, "ioctl(KVM_TRANSLATE) failed: %s\n", strerror(errno));
  //   return -1;
  // }
  // printf("Translation: phys: %#llx valid: %" PRIu8 " writeable: %" PRIu8
  //        " usermode: %" PRIu8 "\n",
  //        translation.physical_address, translation.valid, translation.writeable,
  //        translation.usermode);

  struct kvm_regs regs;
  memset(&regs, 0, sizeof(regs));
  regs.rflags = 0x246;
  regs.rip = (uint64_t)vm_entry;
  //regs.rip = 0x100000;

  if (vcpu_handle.ioctl(KVM_SET_REGS, &regs)) {
    fprintf(stderr, "ioctl(KVM_SET_REGS) failed: %s\n", strerror(errno));
    return -1;
  }

  // struct kvm_guest_debug dbg;
  // memset(&dbg, 0, sizeof(dbg));
  // dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;

keep_going:
  // print_registers(vcpu_handle);

  // if (vcpu_handle.ioctl(KVM_SET_GUEST_DEBUG, &dbg)) {
  //   fprintf(stderr, "ioctl(KVM_SET_GUEST_DEBUG) failed: %s\n", strerror(errno));
  //   return -1;
  // }

  if (vcpu_handle.ioctl(KVM_RUN, 0)) {
    fprintf(stderr, "ioctl(KVM_RUN) failed: %s\n", strerror(errno));
    return -1;
  }

  switch (kvm_run->exit_reason) {
  case KVM_EXIT_UNKNOWN:
    printf("KVM_EXIT_UNKNOWN - hardware_exit_reason: %llu\n",
           kvm_run->hw.hardware_exit_reason);
    break;
  case KVM_EXIT_IO: {
    if (kvm_run->io.port == 0) {
      handle_syscall(vcpu_handle);
      goto keep_going;
    }
    printf("KVM_EXIT_IO\n");
    printf("\t");
    if (kvm_run->io.direction == KVM_EXIT_IO_IN) {
      printf("direction: in\n");
    } else if (kvm_run->io.direction == KVM_EXIT_IO_OUT) {
      printf("direction: out\n");
    } else {
      printf("direction: unknown\n");
    }
    printf("\tsize: %hhu\n", kvm_run->io.size);
    printf("\tport: %hx\n", kvm_run->io.port);
    printf("\tcount: %x\n", kvm_run->io.count);
    printf("\tdata_offset: %llx\n", kvm_run->io.data_offset);
    auto data_addr = (((uint8_t*)kvm_run) + kvm_run->io.data_offset);
    std::cout << "guest out = " << *((uint32_t*)data_addr) << std::endl;
    std::cout << "pid = " << getpid() << std::endl;
    break;
  }
  case KVM_EXIT_DEBUG:
    struct kvm_regs regs;
    if (vcpu_handle.ioctl(KVM_GET_REGS, &regs) < 0) {
      fprintf(stderr, "KVM_GET_REGS failed: %s\n", strerror(errno));
      exit(-1);
    }
    goto keep_going;
    break;
  case KVM_EXIT_HLT:
    printf("KVM_EXIT_HLT\n");
    print_registers(vcpu_handle);
    break;
  case KVM_EXIT_MMIO:
    printf("KVM_EXIT_MMIO\n");
    printf("\taddr: %#18llX\n", kvm_run->mmio.phys_addr);
    printf("\tlen: %#x\n", kvm_run->mmio.len);
    printf("\tis_write: %x\n", kvm_run->mmio.is_write);
    print_registers(vcpu_handle);
    break;
  case KVM_EXIT_SHUTDOWN:
    printf("KVM_EXIT_SHUTDOWN\n");
    print_registers(vcpu_handle);
    break;
  case KVM_EXIT_FAIL_ENTRY:
    printf("KVM_EXIT_FAIL_ENTRY - hardware_entry_failure_reason: %llx\n",
           kvm_run->fail_entry.hardware_entry_failure_reason);
    break;
  case KVM_EXIT_INTERNAL_ERROR:
    printf("KVM_EXIT_INTERNAL_ERROR\n");
    print_registers(vcpu_handle);
    break;
  default:
    printf("exit_reason: %u\n", kvm_run->exit_reason);
    break;
  };

  return 0;
}

extern "C" __attribute__((noreturn)) void vm_c_entry() {
  auto pid = getpid();
  asm volatile("outl %[pid], $0x90"
               : /* no outputs */
               : [pid] "r"(pid));
  asm volatile("hlt");
  while (1)
    ;
}
