#include <stdint.h>

extern int main(void);

extern uint32_t _sidata; /* start of init values for .data in FLASH */
extern uint32_t _sdata;  /* start of .data in RAM */
extern uint32_t _edata;  /* end of .data in RAM */
extern uint32_t _sbss;   /* start of .bss in RAM */
extern uint32_t _ebss;   /* end of .bss in RAM */
extern uint32_t _estack; /* top of stack */

void Reset_Handler(void);
static void Default_Handler(void);

void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void) __attribute__((weak, alias("Default_Handler")));

__attribute__((section(".isr_vector")))
const void *isr_vector[] = {
    (void *)&_estack, /* initial SP */
    Reset_Handler,
    NMI_Handler,
    HardFault_Handler,
    MemManage_Handler,
    BusFault_Handler,
    UsageFault_Handler,
    0,
    0,
    0,
    0,
    SVC_Handler,
    DebugMon_Handler,
    0,
    PendSV_Handler,
    SysTick_Handler,
};

void Reset_Handler(void) {
  /* Copy .data from FLASH to RAM */
  uint32_t *src = &_sidata;
  uint32_t *dst = &_sdata;
  while (dst < &_edata) {
    *dst++ = *src++;
  }

  /* Zero .bss */
  dst = &_sbss;
  while (dst < &_ebss) {
    *dst++ = 0;
  }

  (void)main();

  /* If main returns, trap. */
  while (1) {
  }
}

static void Default_Handler(void) {
  while (1) {
  }
}

