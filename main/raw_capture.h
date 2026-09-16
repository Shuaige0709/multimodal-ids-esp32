#pragma once

// Suppress normal runtime text logs. Boot/panic bytes can still occur; the host resyncs.
void raw_capture_prepare_console(void);
// Requires Wi-Fi initialized. Owns the promiscuous callback and UART0 TX.
void raw_capture_start(void);
