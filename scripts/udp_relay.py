#!/usr/bin/env python3
"""
Simple UDP relay to forward syslog and control packets from a local port to a remote collector.
Usage examples:
    # Forward syslog from 0.0.0.0:1514 to 10.0.0.2:1514 and labels on 9999 unchanged
     python scripts/udp_relay.py --listen-ip 0.0.0.0 --listen-port 1514 --target-ip 10.0.0.2 --target-port 1514 --control-port 9999

Notes:
- Prefer non-privileged ports (>1024) to avoid running as root/admin.
- Keep this relay running on the laptop that ESP32 points to; the relay forwards to the Pi collector.
- Control labels (START/STOP) can be forwarded on 9999 too so the collector receives them.
"""
import argparse
import logging
import select
import socket
import sys
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

BUFFER_SIZE = 4096


def _bind_udp_socket(listen_ip, listen_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((listen_ip, listen_port))
    except PermissionError:
        logging.error("Permission denied binding %s:%d - try using a port >1024 or run as admin/sudo", listen_ip, listen_port)
        sys.exit(2)
    return sock


def run_relay(listen_ip, listen_port, target_ip, target_port, control_port=None, control_target_port=None, verbose=False):
    sockets = []
    routes = {}

    syslog_sock = _bind_udp_socket(listen_ip, listen_port)
    sockets.append(syslog_sock)
    routes[syslog_sock] = (target_ip, target_port, "syslog")

    if control_port is not None and control_target_port is not None:
        ctrl_sock = _bind_udp_socket(listen_ip, control_port)
        sockets.append(ctrl_sock)
        routes[ctrl_sock] = (target_ip, control_target_port, "control")
        logging.info("Control relay enabled on %s:%d -> %s:%d", listen_ip, control_port, target_ip, control_target_port)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logging.info("UDP relay listening on %s:%d -> forwarding to %s:%d", listen_ip, listen_port, target_ip, target_port)

    count = 0
    last_log = time.time()
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 1.0)
            for recv_sock in readable:
                data, addr = recv_sock.recvfrom(BUFFER_SIZE)
                count += 1
                target_ip_addr, target_port_addr, label = routes[recv_sock]
                try:
                    send_sock.sendto(data, (target_ip_addr, target_port_addr))
                except Exception as e:
                    logging.warning("Failed to forward %s packet #%d: %s", label, count, str(e))

                if verbose:
                    logging.debug("%d bytes from %s forwarded as %s", len(data), addr, label)

            if time.time() - last_log > 30:
                logging.info("Forwarded %d packets", count)
                last_log = time.time()
    except KeyboardInterrupt:
        logging.info("Relay stopped by user")
    finally:
        for sock in sockets:
            sock.close()
        send_sock.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='UDP relay for syslog forwarding')
    p.add_argument('--listen-ip', default='0.0.0.0', help='IP to bind locally')
    p.add_argument('--listen-port', type=int, default=514, help='Local port to listen on (use >1024 to avoid sudo)')
    p.add_argument('--target-ip', required=True, help='Destination collector IP')
    p.add_argument('--target-port', type=int, default=514, help='Destination collector port')
    p.add_argument('--control-port', type=int, default=9999, help='Local port for START/STOP labels (set to 0 to disable)')
    p.add_argument('--control-target-port', type=int, default=9999, help='Destination port for START/STOP labels')
    p.add_argument('--verbose', action='store_true')
    args = p.parse_args()

    control_port = None if args.control_port == 0 else args.control_port
    control_target_port = None if args.control_port == 0 else args.control_target_port
    run_relay(args.listen_ip, args.listen_port, args.target_ip, args.target_port, control_port, control_target_port, args.verbose)
