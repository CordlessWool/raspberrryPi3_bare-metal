#include <stdint.h>

#define IO_BASE 0x3f000000
#define GP_BASE (IO_BASE + 0x200000)
#define MU_BASE (IO_BASE + 0x215000)

#define AUX_ENB (*(volatile unsigned *)(MU_BASE + 0x04))
#define MU_IO   (*(volatile unsigned *)(MU_BASE + 0x40))
#define MU_LCR  (*(volatile unsigned *)(MU_BASE + 0x4c))
#define MU_LSR  (*(volatile unsigned *)(MU_BASE + 0x54))
#define MU_CNTL (*(volatile unsigned *)(MU_BASE + 0x60))
#define MU_BAUD (*(volatile unsigned *)(MU_BASE + 0x68))

#define GPFSEL1 (*(volatile unsigned *)(GP_BASE + 0x04))
#define GPPUD   (*(volatile unsigned *)(GP_BASE + 0x94))
#define GPPUDCLK0   (*(volatile unsigned *)(GP_BASE + 0x98))

#define BUSY_WAIT __asm__ __volatile__("")
#define BUSY_WAIT_N 0x100000

static void
init_uart (void)
{
  int i;

  AUX_ENB |= 1;		/* Enable mini-uart */
  MU_LCR = 3;		/* 8 bit.  */
  MU_BAUD = 270;	/* 115200 baud.  */
  GPFSEL1 &= ~((7 << 12) | (7 << 15));	/* GPIO14 & 15: alt5  */
  GPFSEL1 |= (2 << 12) | (2 << 15);

  /* Disable pull-up/down.  */
  GPPUD = 0;

  for (i = 0; i < 150; i++)
    asm volatile ("nop");

  GPPUDCLK0 = (2 << 14) | (2 << 15);

  for (i = 0; i < 150; i++)
    asm volatile ("nop");

  GPPUDCLK0 = 0;

  MU_CNTL = 3;		/* Enable Tx and Rx.  */
}


void
raw_putc (char c)
{
  while (!(MU_LSR & 0x20))
    ;
  MU_IO = c;
}

void
putc (char c)
{
  if (c == '\n')
    raw_putc ('\r');
  raw_putc (c);
}

void
puts (const char *s)
{
  while (*s)
    putc (*s++);
}

int
main (void)
{
  init_uart ();


	uint32_t i;
    /* At the low level, everything is done by writing to magic memory addresses. */
    volatile uint32_t * const GPFSEL4 = (uint32_t *)0x3F200010;
    volatile uint32_t * const GPFSEL3 = (uint32_t *)0x3F20000C;
    volatile uint32_t * const GPSET1  = (uint32_t *)0x3F200020;
    volatile uint32_t * const GPCLR1  = (uint32_t *)0x3F20002C;

    *GPFSEL4 = (*GPFSEL4 & ~(7 << 21)) | (1 << 21);
    *GPFSEL3 = (*GPFSEL3 & ~(7 << 15)) | (1 << 15);
	while(1){  
	  puts ("Hello world!\n");

        *GPSET1 = 1 << (47 - 32);
        *GPCLR1 = 1 << (35 - 32);
        for (i = 0; i < BUSY_WAIT_N; ++i) { BUSY_WAIT; }
        *GPCLR1 = 1 << (47 - 32);
        *GPSET1 = 1 << (35 - 32);
        for (i = 0; i < BUSY_WAIT_N; ++i) { BUSY_WAIT; }

			
	}		

  return 0;
}
