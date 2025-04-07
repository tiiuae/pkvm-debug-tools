
#ifndef __PKVM_MODULE_DBG_TOOLS_CONFIG
#define __PKVM_MODULE_DBG_TOOLS_CONFIG

/* Physical address of UART in the host. */
/* UART in QEMU */
#define  KVM_ARM_HYP_DEBUG_UART_ADDR	0x09000000

/* UART on Nvidia HW */
//#define  KVM_ARM_HYP_DEBUG_UART_ADDR	0x031D0000

/* Hypervisor ramlog collects register dumps and other data separately from
 * a kernel log. Hypervisor log is encrypted with a chacha20 cipher.
 */
#define  HYP_DEBUG_RAMLOG 1

/* For debug purposes it is convenient to read the log instantly
 * in console, the option just enables additional output and does not
 * reject storing and encrypting the log
 */
#define HYP_DEBUG_RAMLOG_DIRECT_PRINT 0
#endif
