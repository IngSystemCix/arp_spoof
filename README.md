
# Herramienta Educativa ARP Spoofing

Aplicación gráfica en Python para realizar ataques de ARP Spoofing en redes locales, con fines educativos y de laboratorio.

## Descripción

Este proyecto permite escanear la red local, identificar dispositivos conectados y realizar ataques de ARP Spoofing para interceptar o cortar la conexión a Internet de una víctima. Incluye una interfaz gráfica fácil de usar, desarrollada con Tkinter.

## Características

- Escaneo automático de la red local para detectar hosts activos.
- Visualización de dispositivos y sus direcciones MAC.
- Ataque ARP Spoofing en modo MITM (intercepta tráfico) o corte total de Internet a la víctima.
- Restauración automática de la red al detener el ataque.
- Interfaz gráfica intuitiva.

## Requisitos

- Python 3.6 o superior
- Permisos de administrador/root
- Paquete: `scapy`

Instalación de dependencias:

```bash
pip install -r requirements.txt
```

## Uso

1. Ejecuta el script principal:
	```bash
	python arp_spoof.py
	```
2. Haz clic en "Escanear Red" para detectar dispositivos.
3. Selecciona el dispositivo objetivo en la lista.
4. Marca "Cortar Internet" si deseas dejar sin acceso a la víctima.
5. Haz clic en "Iniciar Ataque" para comenzar.
6. Detén el ataque con "Detener Ataque" para restaurar la red.

## Advertencia

Esta herramienta es solo para fines educativos y de auditoría autorizada en entornos controlados. El uso indebido puede ser ilegal y está prohibido.

## Licencia

MIT License.
