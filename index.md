---
layout: default
title: Inicio
---

# Windows NT 3.1 — Research Lab

Laboratorio de reversing de **Windows NT 3.1 Advanced Server** en QEMU/KVM, usado como base para estudiar *Inside Windows NT* (Helen Custer, 1992) y la serie *Windows Internals* contra un kernel real.

## Fases documentadas

1. [Instalación base](./README.html) — armado de la VM, instalación de NT 3.1 Advanced Server, bug del CPU Pentium en el instalador
2. [Fase 2 — Kernel Debugger](./02-kernel-debugger-setup.html) — configuración de `I386KD.EXE` y debug remoto por serial virtual
3. [Fase 3 — Visual C++ y DDK](./03-visual-c-ddk-setup.html) — toolchain de compilación de drivers, primer driver real compilado y verificado en vivo
4. [Fase 4 — NtOpenFile](./04-ntopenfile-reversing.html) — `NtOpenFile` como wrapper delgado sobre `IoCreateFile`, aislando funciones del kernel una por una con el kernel debugger
5. [Fase 5 — IoCreateFile](./05-iocreatefile-reversing.html) — reversing completo con Ghidra: tipos DDK auténticos, `RequestorMode`, frame SEH, validaciones de usermode (en curso)

## Créditos

- [WinWorld](https://winworldpc.com) — preservación de software abandonware
- *Inside Windows NT* — Helen Custer (Microsoft Press, 1992)
