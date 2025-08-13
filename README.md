
# ARP Spoof

Herramienta de spoofing ARP desarrollada en Python para pruebas de seguridad en redes locales.

## Descripción

Este proyecto permite realizar ataques de ARP spoofing, interceptando el tráfico entre dispositivos en una red local. Es útil para pentesters, investigadores de seguridad y estudiantes que deseen comprender el funcionamiento de los ataques de intermediario (Man-in-the-Middle).

## Características

- Envío de paquetes ARP falsificados.
- Intercepción de tráfico entre víctima y gateway.
- Fácil de usar y personalizar.
- Basado en Python y Scapy.

## Requisitos

- Python 3.6+
- Permisos de administrador/root
- Paquetes:
	- scapy

Instala las dependencias con:

```bash
pip install -r requirements.txt
```

## Uso

Ejecuta el script con los parámetros necesarios:

```bash
python arp_spoof.py --target <IP_VICTIMA> --gateway <IP_GATEWAY>
```

Opciones disponibles:

- `--target`: IP de la víctima.
- `--gateway`: IP del gateway.
- `--interface`: (Opcional) Interfaz de red a utilizar.

Ejemplo:

```bash
python arp_spoof.py --target 192.168.1.10 --gateway 192.168.1.1 --interface eth0
```

## Advertencia

Este proyecto es solo para fines educativos y de auditoría autorizada. El uso indebido puede ser ilegal.

## Licencia

MIT License.
