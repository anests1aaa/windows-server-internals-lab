---
layout: default
title: Instalación base
---

# Windows NT 3.1 Advanced Server — Lab de Reversing en QEMU

Documentación del proceso completo de instalación de **Windows NT 3.1 Advanced Server (build 3.10.5098.1)** en QEMU/KVM sobre Arch Linux, como base para el estudio de *Inside Windows NT* (Helen Custer, 1992) y el proyecto más amplio de investigar los internals de Windows Server a través de sus distintas versiones.

## Host

- **Sistema operativo:** Arch Linux
- **Hypervisor:** QEMU/KVM (`qemu-system-i386`)
- **Herramientas auxiliares:** `mtools` (manipulación de imágenes FAT sin montar), `p7zip`

```bash
sudo pacman -S qemu-full mtools p7zip
```

## Paso a paso

### 1. Crear el disco duro virtual

```bash
mkdir -p ~/WindowsNT3.1 && cd ~/WindowsNT3.1
qemu-img create -f qcow2 nt31.img 500M
```

### 2. Preparar el disquete de MS-DOS con soporte de CD-ROM

El MS-DOS 6.22 (ni ninguna versión retail de Microsoft) incluye un driver de CD-ROM — cada fabricante de hardware lo distribuía aparte. Hay que agregarlo manualmente al disquete de arranque de DOS.

```bash
# Copiar el disquete 1 de MS-DOS con nombre simple
cp /ruta/a/disk01.img ./dos1.img

# Liberar espacio (el disquete viene casi lleno, ~41KB necesarios para el driver)
mdel -i dos1.img ::QBASIC.EXE
mdel -i dos1.img ::SCANDISK.EXE
mdel -i dos1.img ::SCANDISK.INI
mdel -i dos1.img ::README.TXT
mdel -i dos1.img ::DEFRAG.EXE
mdel -i dos1.img ::DEFRAG.HL_

# Copiar el driver de CD-ROM (OAKCDROM.SYS, driver genérico ATAPI de Oak Technology)
mcopy -i dos1.img OAKCDROM.SYS ::OAKCDROM.SYS
```

Crear `CONFIG.SYS` y `AUTOEXEC.BAT` que carguen el driver y MSCDEX (que ya viene incluido en Disk 1):

```bash
cat > config.sys << 'EOF'
country=001
DEVICE=A:\OAKCDROM.SYS /D:MSCD001
EOF

cat > autoexec.bat << 'EOF'
@echo off
nlsfunc
keyb us
A:\MSCDEX.EXE /D:MSCD001
EOF

mcopy -o -i dos1.img ./config.sys ::CONFIG.SYS
mcopy -o -i dos1.img ./autoexec.bat ::AUTOEXEC.BAT
```

> **Nota:** el mensaje de confirmación de MSCDEX ("Drive D: = Driver MSCD001 unit 0") se pierde en el scroll automático del arranque — no es un error, solo hay que confirmarlo corriendo `A:\MSCDEX.EXE /D:MSCD001` manualmente si hay dudas.

### 3. Particionar y formatear el disco duro

MS-DOS 6.22 "Upgrade" no permite instalarse en un disco completamente vacío por defecto. Truco: mantener **Shift** apretado al arrancar desde el Disk 1 para saltear esa verificación.

```bash
qemu-system-i386 -m 32 -hda nt31.img -fda dos1.img -boot a -M pc,acpi=off -cpu 486
```

Dentro de la VM (con Shift apretado durante el arranque):
```
fdisk
```
→ Create Primary DOS Partition → usar 100% del espacio → Esc para salir → cerrar la VM.

Reiniciar (con Shift apretado de nuevo) y formatear:
```
format c: /s
```

### 4. Copiar los archivos de instalación de NT al disco duro

**Por qué este paso es obligatorio y no opcional:** NT 3.1 es anterior al estándar ATAPI (1994), por lo que el instalador de NT **no puede leer un CD-ROM conectado por IDE**. Solo reconoce CD-ROMs colgados de una controladora SCSI específica de una lista fija de drivers de 1993 (Adaptec 1542/1740, BusLogic, NCR 53C700/710, etc. — ninguno coincide con los chips SCSI que emula QEMU moderno: `lsi53c810`, `lsi53c895a`). La solución es copiar todos los archivos al disco duro usando DOS (que sí lee el CD como IDE/ATAPI normal vía `OAKCDROM.SYS`), y lanzar el instalador desde ahí, evitando que NT necesite tocar el CD en ningún momento.

```bash
qemu-system-i386 -m 32 -hda nt31.img -fda dos1.img -cdrom CD.iso -boot a -M pc,acpi=off -cpu 486
```

Dentro de la VM:
```
c:
mkdir install
a:\expand a:\xcopy.ex_ c:\xcopy.exe
c:\xcopy d:\i386\*.* c:\install\ /e
```

> `XCOPY.EXE` viene comprimido en el disquete (`XCOPY.EX_`) y hay que expandirlo primero con `EXPAND.EXE`.
> El switch `/h` de xcopy dio "Invalid switch" en esta versión — usar solo `/e`.

### 5. Lanzar el instalador de NT

```
c:\install\winnt /f /c
```

- `/f` — evita verificación de integridad de archivos copiados (más rápido en emulación)
- `/c` — salta la verificación de espacio libre en disco

Este paso pide crear "Setup Boot Disks" — disquetes vacíos y **formateados con FAT** (no alcanza con `qemu-img create`, hay que formatearlos):

```bash
qemu-img create -f raw setupdisk1.img 1440K
mformat -i setupdisk1.img -f 1440 ::
```

Cambiar el disquete sin cerrar la VM, vía el monitor de QEMU:
```
Ctrl+Alt+2          # entrar al monitor
change floppy0 /ruta/completa/setupdisk1.img
Ctrl+Alt+1          # volver a la VM
```

### 6. Fase gráfica/texto del Setup

Tras el reinicio automático (tras "The MS-DOS based portion of Setup is now complete"):

1. **Custom vs Express Setup:** Express Setup (Enter) — detección automática, menos puntos de fallo.
2. **Sistema de archivos:** Convert to NTFS (relevante para estudiar el capítulo de NTFS del libro).
3. **Configuración de red:** valores por defecto para la tarjeta emulada (3Com Etherlink II compatible: IRQ 3, I/O 0x300, On Board).
4. **Domain Settings (específico de Advanced Server):** "Controller in New Domain" — crea un dominio nuevo sin depender de infraestructura externa.
5. **Emergency Repair Disk:** requiere otro disquete vacío y **formateado** (mismo procedimiento que el paso anterior con `mformat`).
6. **Reinicio final:** enviar Ctrl+Alt+Delete a través del monitor de QEMU, no del teclado del host:
   ```
   Ctrl+Alt+2
   sendkey ctrl-alt-delete
   Ctrl+Alt+1
   ```

## Comando de arranque para uso diario (post-instalación)

```bash
qemu-system-i386 -m 64 -hda nt31.img -boot c -M pc,acpi=off -cpu 486
```

## Créditos y fuentes

- [WinWorld](https://winworldpc.com) — preservación de software abandonware
- [Computer History Wiki — Installing Windows NT 3.1 on Qemu](https://gunkies.org/wiki/Installing_Windows_NT_3.1_on_Qemu) — confirmación del bug de CPU Pentium
- *Inside Windows NT* — Helen Custer (Microsoft Press, 1992)
