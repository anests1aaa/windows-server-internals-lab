# Fase 3 — Instalación de Visual C++ 1.10 for NT y DDK (toolchain de compilación de drivers)

Continuación de [README.md](./README.md) (instalación base) y [02-kernel-debugger-setup.md](./02-kernel-debugger-setup.md) (kernel debugger). Esta fase documenta cómo armar el toolchain completo de compilación para poder escribir y compilar drivers de kernel contra NT 3.1, verificando después su comportamiento en vivo con `I386KD.EXE`.

## Objetivo

Tener, dentro de la VM debugger (`nt31-debugger.img`), un entorno funcional de:
- Compilador C para i386 (`CL386.EXE`)
- Headers y libs de kernel del DDK (`NTDDK.H`, etc.)
- `BUILD.EXE` (el driver de build oficial del DDK)
- Samples de drivers para usar como punto de partida

## Fuentes de software (adicionales al README original)

| Componente | Origen | Notas |
|---|---|---|
| Windows NT 3.1 Win32 SDK and DDK (Oct 1994, MSDN ISO) | WinWorld | Trae compilador i386 para MIPS/Alpha pero **no** para x86 — ver más abajo |
| Microsoft Visual C++ 1.10 for Windows NT & 32s | archive.org | Trae `CL386.EXE`, el compilador i386 que falta en el DDK |

## ⚠️ Hallazgo: el DDK de NT 3.1 no trae compilador para i386

El SDK/DDK bundle de esta build (Oct 1994) incluye carpetas `ALPHA`, `MIPS` e `I386`, pero **`I386` son archivos de instalación de NT para esa arquitectura, no el compilador**. El compilador C (`CL.EXE`) solo está presente en `MSTOOLS/BIN/MIPS` y `MSTOOLS/BIN/ALPHA` — confirmado también por reportes del foro de WinWorld sobre este mismo paquete.

**Solución:** conseguir **Microsoft Visual C++ 1.10 for Windows NT & 32s** aparte (mismo período/versión del compilador que el usado internamente por el SDK para MIPS/Alpha — versión 8.00). Ahí sí está `CL386.EXE`, junto con `LINK32.EXE`, `LIB32.EXE`, `NMAKE.EXE` y el runtime `DOSXNT.EXE` (DPMI, permite correr el toolchain de 32 bits desde DOS/NT sin problema).

## Comandos usados

```bash
# Crear disco intermedio para Visual C++
qemu-img create -f qcow2 devtools.img 200M

# Armar ISO del instalador desde el host (mkisofs, paquete cdrtools en Arch)
cd ~/Downloads/VisualC
mkisofs -o msvcnt.iso -J -r MSVCNT/

# VM temporal de DOS para preparar el disco intermedio
qemu-system-i386 -m 32 -hda devtools.img -fda dos1.img -cdrom ~/Downloads/VisualC/msvcnt.iso -boot a -M pc,acpi=off -cpu 486
```

Mismo procedimiento se repitió para el DDK (74MB), con un disco intermedio más chico:

```bash
# Extraer solo la carpeta DDK del SDK completo (no hace falta I386/MIPS/ALPHA, que son archivos de instalación de NT)
cd "~/Downloads/.../SDKISO"
mkisofs -o ddk.iso -J -r DDK/

qemu-img create -f qcow2 ddktools.img 150M
qemu-system-i386 -m 32 -hda ddktools.img -fda dos1.img -cdrom ddk.iso -boot a -M pc,acpi=off -cpu 486
```

## Instalación de Visual C++ dentro de la VM debugger

Con `devtools.img` ya preparado, se arrancó la VM debugger con dos discos:

```bash
qemu-system-i386 -m 64 -hda nt31-debugger.img -hdb devtools.img -M pc,acpi=off -cpu 486
```

`devtools.img` apareció correctamente como `D:` en el File Manager (confirmando que el problema era específicamente ATAPI, no un límite general de NT con discos adicionales). Desde ahí:

```
D:\MSVCNT\SETUP.EXE
```

- Tipo de instalación: **Complete** (había espacio de sobra, 364MB libres de 499MB totales — no hacía falta optimizar con Custom)
- Al finalizar, el instalador preguntó cómo manejar `TOOLS.INI`: se eligió **"Make changes now and back up current version"** (en vez de la opción por default, que solo escribe una copia modificada en otro lugar sin aplicarla) — así los cambios quedan aplicados directamente y el archivo es inspeccionable después

Una vez instalado `MSVCNT` en `C:`, el disco `D:` (con los instaladores) ya no es necesario para el uso diario del compilador — se puede omitir del comando de arranque en sesiones futuras.

## Extraer archivos de una VM con C: en NTFS, sin arrancarla

Necesitábamos leer `TOOLS.INI` y `VCVARS32.BAT` desde el host para saber cómo Visual C++ configura sus variables de entorno (`INCLUDE`, `LIB`, `PATH`), sin tener que ir sacando capturas de pantalla de Notepad una por una.

**Intento fallido: `libguestfs` (`guestmount`, `virt-copy-out`, `guestfish`).** Los tres fallaron con el mismo error de fondo:
```
mount: wrong fs type, bad option, bad superblock on /dev/sda1
```
La causa es que **NT 3.1 usa una versión muy temprana de NTFS** ("NTFS v1.0"), con estructuras internas distintas a las que reconoce el driver `ntfs-3g`/`ntfs3` moderno de Linux — el mismo driver que usan por debajo todas las herramientas de `libguestfs`. `virt-copy-out` además falla con un segundo problema previo: intenta hacer inspección automática del SO en el disco y no reconoce NT 3.1 como sistema instalado, así que ni siquiera llega a montar.

**Solución que funcionó: disquete FAT intermedio.** Mismo mecanismo de `mtools` que ya se usaba en la Fase 2 para meter `I386KD.EXE` en la VM — pero en sentido inverso, para sacar archivos:

```bash
qemu-img create -f raw extract.img 1440K
mformat -i extract.img -f 1440 ::
```

Insertar el disquete vía monitor de QEMU sin apagar la VM:
```
Ctrl+Alt+2
change floppy0 /home/s1a/WindowsNT3.1/extract.img
Ctrl+Alt+1
```

Copiar el archivo deseado al disquete desde dentro de NT:
```
copy C:\MSVCNT\TOOLS.INI A:\
copy C:\MSVCNT\BIN\VCVARS32.BAT A:\
```

Y leerlo desde el host con `mtools` (que sí funciona perfecto con FAT, sin ningún problema de compatibilidad):
```bash
mtype -i extract.img ::TOOLS.INI
mtype -i extract.img ::VCVARS32.BAT
```

Esto evita por completo el problema de NTFS viejo, ya que el disquete es FAT de punta a punta.

## Configuración de variables de entorno

`TOOLS.INI` solo contiene configuración del profiler (exclusión de libs) — **no** las variables de compilación. Esas viven en `VCVARS32.BAT`:

```batch
@echo off
set PATH=C:\MSVCNT\BIN;%PATH%
set INCLUDE=C:\MSVCNT\INCLUDE;C:\MSVCNT\MFC\INCLUDE;%INCLUDE%
set LIB=C:\MSVCNT\LIB;C:\MSVCNT\MFC\LIB;%LIB%
set INIT=C:\MSVCNT;%INIT%
```

Para sumar las rutas del DDK sin romper esta configuración base, se armó un segundo batch, `SETDDK.BAT`, que llama a `VCVARS32.BAT` primero y extiende las variables después:

```batch
@echo off
call C:\MSVCNT\BIN\VCVARS32.BAT
set INCLUDE=D:\INC;%INCLUDE%
set LIB=D:\LIB;%LIB%
set PATH=D:\BIN\I386\FREE;%PATH%
```

`SETDDK.BAT` se armó en el host y se metió en la VM con el mismo mecanismo del disquete FAT (esta vez en sentido host → VM, como en la Fase 2):

```bash
mcopy -i extract.img /tmp/setddk.bat ::SETDDK.BAT
```

## Comando de arranque para desarrollo (post-setup)

```bash
qemu-system-i386 -m 64 -hda nt31-debugger.img -hdb ddktools.img -M pc,acpi=off -cpu 486
```

Dentro de NT, antes de compilar:
```
C:\SETDDK.BAT
```

## Estructura final de discos en la VM debugger

| Unidad | Contenido |
|---|---|
| `C:` | NT 3.1 Advanced Server + Visual C++ 1.10 instalado (`C:\MSVCNT`) + `I386KD` + `SYMBOLS` (de la Fase 2) |
| `D:` | DDK completo (`INC`, `LIB`, `SRC`, `BIN`, `DOC`) |

## Problemas encontrados y descartados (para referencia)

| Intento | Resultado | Causa |
|---|---|---|
| `-cdrom` con ISO del instalador de Visual C++, sobre NT ya instalado | CD nunca aparece como unidad, sin error visible | Mismo bug ATAPI del README original — no es solo del instalador de NT, es de todo NT 3.1 |
| `guestmount -m /dev/sda1` sobre `nt31-debugger.img` | `wrong fs type, bad superblock` | NTFS v1.0 (NT 3.1) no es reconocido por el driver `ntfs-3g` moderno |
| `virt-copy-out` sin inspección manual | `no operating system was found on this disk` | El inspector automático de libguestfs no reconoce NT 3.1 como SO instalado |
| `guestfish` + `mount-ro` manual | Mismo error de superbloque que `guestmount` | Confirma que el problema es el driver NTFS, no la herramienta específica |

## Corrección: el entorno de build real es `SETENV.BAT`, no variables sueltas

El primer `SETDDK.BAT` armado a mano (`set INCLUDE=...`, `set LIB=...`) resultó insuficiente. El `MAKEFILE` de cualquier sample del DDK depende de un entorno de build completo, indicado por esta línea:

```
!INCLUDE $(NTMAKEENV)\makefile.def
```

`NTMAKEENV`, `BASEDIR`, `DDKBUILDENV`, `BUILD_DEFAULT_TARGETS`, etc. las setea el script oficial del DDK, `DDK/BIN/SETENV.BAT` — que además detecta la arquitectura vía la variable `PROCESSOR_ARCHITECTURE` (ya seteada por NT, confirmada en `x86`).

`SETDDK.BAT` final, combinando Visual C++ + el entorno oficial del DDK + el `PATH` a `BUILD.EXE` (que `SETENV.BAT` no agrega solo — solo suma `%BASEDIR%\bin`, no la subcarpeta específica de arquitectura donde vive el binario real):

```batch
@echo off
call C:\MSVCNT\BIN\VCVARS32.BAT
call C:\DD\DD\BIN\SETENV.BAT C:\DD\DD free
set PATH=C:\DD\DD\BIN\I386\FREE;%PATH%
```

> **Nota sobre `C:\DD\DD`:** el DDK terminó copiado con esa estructura (carpeta duplicada) por un detalle del "Move" hecho desde el File Manager al pasar `D:\DD` (el disco intermedio del ISO) a `C:\DD` — el resultado fue `C:\DD\DD\...` en vez de `C:\DD\...`. No afecta nada funcionalmente, solo hay que tenerlo en cuenta en cualquier ruta.

Con esto, `BASEDIR=C:\DD\DD`, `NTMAKEENV=C:\DD\DD\INC`, `DDKBUILDENV=free` — confirmado con `echo` de cada variable.

## Primer build exitoso: `INPORT.SYS`

Como candidato para la primera compilación de prueba se descartaron los samples de `krnldbg` (son herramientas del propio debugger — `kdapis` es la librería del protocolo de comunicación serial, `kdexts` son extensiones para `i386kd`/`windbg`, ninguno es un driver de carga real) y se comparó tamaño de fuente entre `comm\oldpar` (73KB, con message compiler aparte) y `input\inport` (94KB en dos `.C`, sin piezas de build adicionales). Se eligió **`INPORT`** — driver del mouse serie "InPort" (bus mouse propietario Microsoft/ATI de los 90).

```
cd C:\DD\DD\SRC\INPUT\INPORT
build
```

Resultado:
```
BUILD: Compile and Link for i386
BUILD: Computing Include file dependencies:
BUILD: Examining c:\dd\dd\src\input\inport directory for files to compile.
- 3 source files (97,788 lines)
BUILD: Compiling c:\dd\dd\src\input\inport directory
Compiling - inport.rc for Unknown Target
Compiling - i386\inpcmn.c for i386
Compiling - i386\inpdep.c for i386
BUILD: Linking c:\dd\dd\src\input\inport directory
Linking Executable - C:\DD\DD\lib\i386\free\inport.sys for i386
BUILD: Done

    3 files compiled - 97564 LPS
    1 executables built
```

Toolchain confirmado de punta a punta: `CL386` compiló contra los headers del DDK, `LINK32` generó `INPORT.SYS` — un driver real de kernel. No se generaron símbolos (`INPORT.DBG`) a pesar de `NTDBGFILES=1` en `SETENV.BAT` — relevante para la sesión de debugging más abajo.

## ⚠️ Incidente: `INACCESSIBLE_BOOT_DEVICE` en `nt31.img`

Al reiniciar la VM target (`nt31.img`) para continuar con la carga del driver, el sistema no bootea más — pantalla azul `STOP: 0x0000007B — INACCESSIBLE_BOOT_DEVICE`, tanto en la entrada `[DEBUG]` como en la normal del menú de boot. Los drivers de disco (`Atdisk.sys`, `Ftdisk.sys`) cargan bien; el fallo ocurre al intentar montar el volumen NTFS.

**Causa más probable:** apagados abruptos de VMs (cerrar la ventana de QEMU en vez de un shutdown prolijo) en algún punto de una sesión larga con mucho intercambio de discos y ventanas — tolerable en las VMs de DOS puro usadas para los discos intermedios, pero `nt31.img` tiene `C:` en **NTFS**, sensible a corrupción de metadata (MFT, boot sector) ante un corte sucio.

**Intento de reparación vía Emergency Repair Disk:** se rearmó el flujo completo de reparación de NT 3.1 (`bootdisk.img` como Setup Boot Disk → tecla `R` en la pantalla de bienvenida → inserción del ERD) — pero el proceso de reparación en sí también requiere un CD-ROM SCSI reconocido para verificar contra los archivos originales, y ahí vuelve a aparecer el bug de origen del proyecto (sin chip SCSI de 1993 emulado por QEMU, ni para instalar ni para reparar). `ENTER` no avanza más allá de esa pantalla — bloqueo duro, sin salida por este camino.

**Solución aplicada: restaurar clonando desde `nt31-debugger.img`** (que seguía sano, y que en la Fase 2 se había clonado *desde* `nt31.img` después de la edición del `BOOT.INI` con la entrada `[DEBUG]`):

```bash
mv nt31.img nt31-broken.img
cp nt31-debugger.img nt31.img
```

Efecto colateral (sin impacto funcional, solo de prolijidad del lab): al ser clon de la VM debugger, `nt31.img` restaurado hereda también `C:\MSVCNT` y `C:\DD\DD` — las dos VMs dejaron de tener el diseño original "target liviana vs. debugger con herramientas" y pasaron a ser equivalentes en contenido.

## Carga del driver como servicio (sin tocar el mouse real)

Para no arriesgar el mouse emulado de la VM, `INPORT.SYS` se registró como servicio nuevo e independiente, con arranque **manual** (no automático), usando `REGINI.EXE` (ya presente en el DDK clonado):

```
\Registry\Machine\System\CurrentControlSet\Services\TestInport
    Type = REG_DWORD 0x00000001
    Start = REG_DWORD 0x00000003
    ErrorControl = REG_DWORD 0x00000001
    ImagePath = REG_SZ System32\Drivers\INPORT.SYS
```

> `Start=3` es `SERVICE_DEMAND_START` — la escala de `Start` en el registro de NT es *menor = más automático/temprano* (`0`=boot, `1`=system, `2`=auto, `3`=manual/demand, `4`=disabled), no al revés.

```
C:\DD\DD\BIN\I386\FREE\REGINI.EXE C:\INPORT.INI
```

Confirmado en `REGEDT32.EXE`, clave `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TestInport` con los 4 valores esperados.

`INPORT.SYS` copiado a `C:\WINNT\SYSTEM32\DRIVERS\` en la VM target — dato importante confirmado en la práctica: **copiar el `.SYS` a esa carpeta no lo carga por sí solo**; solo la entrada de registro (`Start`) decide si y cuándo arranca.

## Sesión de debugging en vivo: verificando la carga real del driver

Con las dos VMs conectadas por serial (mismo patrón de la Fase 2 — `nt31.img` como servidor del socket, `nt31-debugger.img` como cliente), se puso en evidencia un problema de orden de arranque: si el cliente (`-serial tcp:127.0.0.1:4555`) arranca **antes** que el servidor (`-serial tcp::4555,server,nowait`), la conexión queda muerta silenciosamente — QEMU no reintenta solo. Solución aplicada: reiniciar el cliente después de confirmar que el servidor ya está arriba (la versión de QEMU usada no soportó el parámetro `reconnect=`/`reconnect-ms=` para automatizar esto).

Otro problema de timing: el menú de boot de NT (`timeout=30` en `BOOT.INI`) hacía perder la ventana para elegir manualmente la entrada `[DEBUG]` con las flechas. Solución: reordenar `BOOT.INI`, poniendo la entrada `[DEBUG]` completa (string + switches) como `default=`, con `timeout` reducido — así arranca en modo debug sin intervención. Un detalle de QEMU a tener en cuenta: **`system_reset` desde el monitor preserva la relectura correcta del `BOOT.INI` editado**; un apagado y reencendido completo del proceso, en un intento anterior de la sesión, no lo hizo de forma consistente.

### El mensaje "Unable to load debug information" no era transitorio

En la Fase 2 se había asumido que ese mensaje se resolvía solo tras la primera interrupción real — resultó ser una asunción incorrecta nunca puesta a prueba: los comandos usados entonces para "confirmar" (`r`, `k`) no requieren símbolos para funcionar. Con símbolos realmente no cargados, comandos que sí dependen de ellos (`x nt!IopLoad*`, `ln eip`) no devolvían nada.

**Causa encontrada:** `C:\SYMBOLS` tenía los `.DBG` copiados sueltos en la raíz, pero `I386KD` espera la estructura por tipo de archivo del CD original (`SYMBOLS\EXE\`, `SYMBOLS\DLL\`, etc.):

```
mkdir C:\SYMBOLS\EXE
mkdir C:\SYMBOLS\DLL
copy C:\SYMBOLS\NTOSKRNL.DBG C:\SYMBOLS\EXE\
copy C:\SYMBOLS\HAL.DBG C:\SYMBOLS\DLL\
```

Confirmado al reiniciar `i386kd`: `KD: Preloading kernel symbols from C:\SYMBOLS\exe\ntoskrnl.DBG` (sin el "Unable to load" previo), y el break automático mostrando nombre simbólico real: `NT!_KeUpdateSystemTime+0x109`.

### Localizar el punto de carga del driver sin símbolos propios de `INPORT.SYS`

Como el build no generó `INPORT.DBG`, se usó una función del **kernel** (con símbolos vía `NTOSKRNL.DBG`) que se ejecuta en cualquier carga de driver: `NT!_IopLoadDriver`, encontrada vía búsqueda de wildcard:

```
kd> x nt!IopLoad*
80188770  NT!_IopLoadDriver
801452d6  NT!_IopLoadFileSystemDriver
801882b0  NT!_IopLoadUnloadDriver
```

```
kd> bp NT!_IopLoadDriver
kd> g
```

Disparado desde la VM target con `net start TestInport`, el breakpoint pegó, confirmando en el stack trace (`k`) la cadena completa que describe *Inside Windows NT* sobre el I/O Manager: la carga de un driver corre en un **worker thread del sistema**, asíncrono respecto al proceso que la solicitó —

```
NT!_PspSystemThreadStartup+0x50
  → NT!_ExpWorkerThread+0x88
    → NT!_IopLoadUnloadDriver+0x57
      → NT!_IopLoadDriver
```

### Delimitar el rango de una función sin símbolos de tamaño (técnica: `ln` sobre el nombre)

Para poder desensamblar la función completa sin pasarse a la siguiente ni quedarse corto, usar `ln` con el nombre simbólico (sin offset) devuelve los dos símbolos más cercanos — el propio y el siguiente en el binario — delimitando el rango exacto:

```
kd> ln nt!_IopLoadDriver
(80188770)  NT!_IopLoadDriver  |  (80188d40)  NT!_IopReadyDeviceObjects
```

Rango de `IopLoadDriver`: `80188770` a `80188d3F` (tamaño `0x5D0`). Desensamblado completo, redirigido a log para evitar el scroll de la consola:

```
kd> .logopen C:\iopload.log
kd> u 80188770 L5d0
kd> .logclose
```

Log extraído por disquete al host (mismo mecanismo de `mtools` de toda la fase) y analizado con `grep`/`awk` filtrando por rango de direcciones, para descartar contaminación de funciones vecinas capturadas en el mismo log.

**Hallazgo:** `IopLoadDriver` no llama a `IoCreateFile`/`ZwOpenFile` directamente — delega la apertura y el mapeo del binario a `NT!_MmLoadSystemImage` (Memory Manager), un nivel de abstracción más abajo de lo esperado. Confirma en la práctica la separación de responsabilidades entre componentes del Executive que describe el libro: el I/O Manager arma el path a partir del registro, pero es el Memory Manager quien efectivamente abre y mapea el archivo.

También se confirmó, filtrando el desensamblado por rango de direcciones (todos los saltos de error convergen a `jmp +0x587`), que **la función tiene un único punto real de salida** — patrón de epílogo único común en el código de esta era.

### Lectura en vivo del `UNICODE_STRING` con el path del driver

Breakpoint puesto justo antes de la llamada al Memory Manager:

```
kd> bp 80188a64      ; call NT!_MmLoadSystemImage
kd> g
```

(disparado de nuevo con `net start TestInport` / `net stop TestInport` desde la VM target)

Con el breakpoint activo, los argumentos ya armados en el stack (`dd esp L10`) muestran un puntero a una `UNICODE_STRING` local (estructura de 8 bytes: `Length`+`MaximumLength` empaquetados + puntero a `Buffer`):

```
kd> dd fe37bed4 L2
kd> du fe747b28
fe747b28   "\SystemRoot\System32\Drivers\INP"
fe747b68   "ORT.SYS"
```

**Confirmación en vivo, en memoria del kernel real:** `\SystemRoot\System32\Drivers\INPORT.SYS` — el path completo armado por `IopLoadDriver` a partir de la clave de registro, justo antes de pasarlo al Memory Manager para el mapeo real del binario.

### Resultado funcional de la carga

`net start TestInport` retorna `System error 20 — The system cannot find the device specified`. Resultado esperado y correcto: `INPORT.SYS` es el driver de un bus mouse propietario que QEMU no emula — el binario compila, carga, ejecuta su `DriverEntry`, busca el hardware físico InPort, no lo encuentra, y falla limpiamente. Confirma que el toolchain completo (compilación + carga + ejecución en kernel real) funciona de punta a punta; el único punto de falla es la ausencia del hardware específico, no del software.

## Próximos pasos del proyecto

- [x] Instalar Visual C++ 1.10 for NT (compilador i386) en la VM debugger
- [x] Instalar DDK de NT 3.x (headers, libs, samples, `BUILD.EXE`)
- [x] Resolver acceso a archivos de una VM con `C:` en NTFS desde el host (vía disquete FAT + `mtools`, dado que `libguestfs` no soporta NTFS v1.0)
- [x] Armar `SETDDK.BAT` combinando entorno de Visual C++ + DDK (usando el `SETENV.BAT` oficial del DDK)
- [x] Compilar un primer driver real (`INPORT.SYS`) con `BUILD.EXE` como prueba de humo del toolchain completo
- [x] Recuperar `nt31.img` de un `INACCESSIBLE_BOOT_DEVICE` (clonado desde `nt31-debugger.img`, ante el límite estructural del ERD con el mismo bug de CD-ROM SCSI del proyecto)
- [x] Cargar el driver como servicio (`REGINI.EXE`, arranque manual) y verificar en vivo con `I386KD.EXE` — breakpoint en `NT!_IopLoadDriver`, delimitación de función sin símbolos propios (`ln` sobre nombre), hallazgo de `MmLoadSystemImage` como responsable real de abrir el archivo, y lectura del `UNICODE_STRING` con el path completo del driver en memoria del kernel


## Créditos y fuentes

- [WinWorld](https://winworldpc.com) — SDK/DDK de NT 3.x
- [Internet Archive — Microsoft Visual C++ 1.10 for Windows NT](https://archive.org/details/microsoft-visual-c-1.10-for-windows-nt)
- Foro de WinWorld — confirmación de que el DDK de NT 3.x requiere Visual C++ 1.0 for NT para compilador i386
- *Inside Windows NT* — Helen Custer (Microsoft Press, 1992)
