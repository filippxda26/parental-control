#ifndef PARENTAL_CONTROL_DNS_H
#define PARENTAL_CONTROL_DNS_H

#define PC_DNS_PORT_BASE 53000
#define PC_DNS_MAX_DEVICES 128

/* A DNS listener is identified by the device's position in devices.json. */
int pc_dns_start(void);
int pc_dns_ready(int device_index);

#endif
