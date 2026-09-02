---
layout: default
title: Fase 6 — ObOpenObjectByName
---

# Fase 6 — Reversing de `ObOpenObjectByName`

Continuación directa de la [Fase 5](./05-iocreatefile-reversing.md): `IoCreateFile` entrega el control al Object Manager genérico vía `ObOpenObjectByName` (`0x80125f86`), pasándole el `OPEN_PACKET` armado como `ParseContext`. Esta fase reversea esa función — el nivel siguiente de la pila.

Herramientas: Ghidra 11 (`ghidra_projects/`) para el análisis estático, `i386kd` sobre la VM de debug (`nt31-debugger.img`, conectada por serial a `nt31.img`) para confirmar todo en vivo.

---

## 1. Los 7 parámetros

Firma ya confirmada en la Fase 5 contra la llamada real desde `IoCreateFile`:

```c
NTSTATUS ObOpenObjectByName(
    POBJECT_ATTRIBUTES ObjectAttributes,
    POBJECT_TYPE        ObjectType,       // OPTIONAL
    KPROCESSOR_MODE      AccessMode,
    PACCESS_STATE         AccessState,     // OPTIONAL
    ACCESS_MASK            DesiredAccess,
    PVOID                   ParseContext,   // el OPEN_PACKET
    PHANDLE                  Handle
);
```

Detalle de cada uno, confirmado contra `ddk_extract/INC/NTDEF.H` y `NTDDK.H` (DDK octubre 1994):

### `ObjectAttributes` — `POBJECT_ATTRIBUTES`

```c
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
```

`RootDirectory` es el ancla para nombres relativos (equivalente al `dirfd` de `openat()`); `ObjectName` es el nombre a resolver en el namespace jerárquico único del Object Manager. `Attributes` es un bitmask (`OBJ_INHERIT`, `OBJ_PERMANENT`, `OBJ_EXCLUSIVE`, `OBJ_CASE_INSENSITIVE`, `OBJ_OPENIF`). Un objeto solo necesita nombre si otro proceso no emparentado tiene que encontrarlo sin herencia ni `DuplicateHandle` explícito (el caso general de IPC por nombre: secciones/shared memory, mutexes, eventos, named pipes).

### `ObjectType` — `POBJECT_TYPE`

```c
typedef struct _OBJECT_TYPE *POBJECT_TYPE;   // NTDDK.H:40, "types that are not exported"
```

Opaco — nunca publicado, mismo bloque que `EPROCESS`/`KTHREAD`. Es un token de verificación de tipo (`OPTIONAL`), confirmado por su uso en `ObReferenceObjectByHandle`/`ObReferenceObjectByPointer` (`NTDDK.H:8873-8888`). Acá viene `NULL` — `IoCreateFile` no sabe todavía si el nombre resuelve a archivo/directorio/dispositivo, delega el chequeo de tipo a su propia validación manual sobre `OPEN_PACKET.local_6c` (Fase 5, Sección 12) en vez de imponerlo acá.

### `AccessMode` — `KPROCESSOR_MODE`

```c
typedef CCHAR KPROCESSOR_MODE;
typedef enum _MODE { KernelMode, UserMode, MaximumMode } MODE;
```

Es el mismo valor que `RequestorMode` (Fase 5, Sección 3 — leído de `KTHREAD->PreviousMode`), y el mismo campo que aparece dentro de `struct _IRP` (`NTDDK.H:7380`, *"mode of the original requestor of this operation"*). Se propaga hasta `SeAccessCheck` (`NTDDK.H:6560-6571`), que también toma `KPROCESSOR_MODE AccessMode` — es el mecanismo por el cual `KernelMode` saltea el chequeo de ACL (documentado en la literatura pública de NT internals, no en este DDK).

### `AccessState` — `PACCESS_STATE`

```c
typedef struct _ACCESS_STATE {
   LUID OperationID;
   BOOLEAN SecurityEvaluated;
   BOOLEAN AuditHandleCreation;
   BOOLEAN GenerateOnClose;
   BOOLEAN PrivilegesAllocated;
   ULONG Flags;
   ACCESS_MASK RemainingDesiredAccess;
   ACCESS_MASK PreviouslyGrantedAccess;
   ACCESS_MASK OriginalDesiredAccess;
   SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
   PSECURITY_DESCRIPTOR SecurityDescriptor;
   PPRIVILEGE_SET PrivilegesUsed;
   union {
      INITIAL_PRIVILEGE_SET InitialPrivilegeSet;
      PRIVILEGE_SET PrivilegeSet;
      } Privileges;
   } ACCESS_STATE, *PACCESS_STATE;
```

Acumulador del estado de un access-check en curso (`OperationID` para auditoría — relevante en esta build, la **Advanced Server** apunta a compliance C2 —, `SubjectSecurityContext` con el token del que pide acceso). Viene `NULL` en esta llamada: le dice al Object Manager que arme el suyo desde cero (ver Sección 3 más abajo). El campo `Flags` no tiene bitmask documentado en este DDK — **pendiente, sin confirmar qué representa cada bit**.

### `DesiredAccess` — `ACCESS_MASK`

```c
typedef ULONG ACCESS_MASK;
#define DELETE 0x00010000L
#define READ_CONTROL 0x00020000L
#define WRITE_DAC 0x00040000L
#define WRITE_OWNER 0x00080000L
#define SYNCHRONIZE 0x00100000L
#define STANDARD_RIGHTS_REQUIRED 0x000F0000L
#define GENERIC_READ 0x80000000L
#define GENERIC_WRITE 0x40000000L
#define GENERIC_EXECUTE 0x20000000L
#define GENERIC_ALL 0x10000000L
```

Layout estándar de 32 bits de NT: 16 bits bajos específicos de tipo, medio los standard rights, 4 bits altos los genéricos (traducidos vía `GenericMapping`, ver Sección 3).

### `ParseContext` / `Handle`

`ParseContext` es el `OPEN_PACKET` ya armado en la Fase 5 (Sección 11) — blob opaco para el Object Manager, solo tiene sentido para el `ParseProcedure` del filesystem. `Handle` (`PHANDLE` = `HANDLE*`, `NTDEF.H:206-212`) es puro output: `&local_18`, el mismo que termina copiado a `*FileHandle` en el epílogo de `IoCreateFile`.

---

## 2. Entrada — validación y `Pointer_ObjectType`

![Decompile de Ghidra: inicialización de Pointer_ObjectType, NULL-check de ObjectAttributes, rama AccessState==NULL](img/obopenobjectbyname-ghidra-entry-nullcheck-accessstate-branch.png)

```c
25  Pointer_ObjectType = (POBJECT_TYPE)0x0;
26  local_88 = 0;
27  if (ObjectAttributes == (POBJECT_ATTRIBUTES)0x0) {
28      return -0x3fffffff3;
29  }
30  if (AccessState == (PACCESS_STATE)0x0) {
31    if (ObjectType != (POBJECT_TYPE)0x0) {
32      Pointer_ObjectType = ObjectType + 0x38;
33    }
34    iVar1 = func_0x80168610(&_Stack_74.PreviouslyGrantedAccess,DesiredAccess,Pointer_ObjectType);
35    if (iVar1 < 0) {
36      return iVar1;
37    }
38    AccessState = (PACCESS_STATE)&_Stack_74.PreviouslyGrantedAccess;
39  }
```

**Línea 25-26:** `Pointer_ObjectType` (local, `POBJECT_TYPE`) y `local_88` arrancan en `0` — acumuladores que se llenan más adelante, no constantes.

**Línea 27-28:** `ObjectAttributes` es el único parámetro no-`OPTIONAL` de verdad (sin nombre no hay nada que resolver) — primer chequeo defensivo, falla rápido con `STATUS_INVALID_PARAMETER` (`-0x3fffffff3` = `0xC000000D`, confirmado en `NTSTATUS.H:1081`).

**Línea 30:** `AccessState == NULL` — en nuestra llamada es cierto, entra al bloque. Confirma en vivo lo predicho: sin `ACCESS_STATE` provisto desde afuera, la función arma el suyo propio en el stack (`_Stack_74`, tipada `_ACCESS_STATE`).

**Línea 31-32:** `Pointer_ObjectType = ObjectType + 0x38` — **solo si `ObjectType` no es `NULL`** (no es nuestro caso: `ObjectType` viene `0` desde `IoCreateFile`, así que esta rama no se ejecuta y `Pointer_ObjectType` se queda en `0`). Es el primer dato concreto de layout que sacamos de la struct opaca `_OBJECT_TYPE`: offset `+0x38`. **Hipótesis sin confirmar:** candidato a ser el campo `GenericMapping` del tipo — el argumento 3 de `func_0x80168610` calza con el patrón "traducir `GENERIC_READ/WRITE/EXECUTE/ALL` según el `GENERIC_MAPPING` del tipo", el mismo parámetro que aparece en la firma de `SeAccessCheck`.

---

## 3. La llamada a `SeCreateAccessState`

`func_0x80168610` resuelve por símbolo en `i386kd` como `NT!_SeCreateAccessState` — rutina interna del Security subsystem (`Se*`), no exportada ni documentada en este DDK (mismo patrón que `ObpLookupObjectName`).

### El Decompile mostraba 3 argumentos — el Listing revela 4

```c
iVar1 = func_0x80168610(&_Stack_74.PreviouslyGrantedAccess, DesiredAccess, Pointer_ObjectType);
```

Pero el Listing real tiene **4 `push`**, no 3:

![Listing de Ghidra: las 4 instrucciones PUSH antes del CALL a SeCreateAccessState](img/obopenobjectbyname-ghidra-secreateaccessstate-4-pushes.png)

```
80125fc4  6a 00              PUSH  0x0
80125fc6  50                 PUSH  Pointer_ObjectType
80125fc7  8b 84 24 c0 00 00 00   MOV  Pointer_ObjectType, dword ptr [ESP + DesiredAccess]
80125fce  50                 PUSH  Pointer_ObjectType
80125fcf  8d 44 24 50        LEA   Pointer_ObjectType=>local_60, [ESP + 0x50]
80125fd3  50                 PUSH  Pointer_ObjectType
                              SeCreateAccessState
80125fd4  e8 37 26 04 00     CALL  SUB_80168610
```

**Trampa de lectura:** `Pointer_ObjectType` aparece como nombre en 3 `push` distintos, pero **no es el mismo valor las 3 veces** — Ghidra le puso ese nombre al registro `EAX`, que se reutiliza como scratch. En cada punto vale algo distinto: `0` (el `Pointer_ObjectType` real, sin tocar) → luego se pisa con `DesiredAccess` (`mov`) → luego se vuelve a pisar con `&local_60` (`lea`). El Decompile se comió el primer `push 0x0` porque a `SUB_80168610` todavía no se le fijó una firma (Ghidra adivina el conteo de argumentos).

Orden real (stdcall pushea al revés de la firma en C — el último push es el 1er parámetro):

| Push (orden de ejecución) | Valor real | Parámetro (orden C) |
|---|---|---|
| 1. `push 0x0` | `0` | 4to |
| 2. `push Pointer_ObjectType` | `0` | 3ro |
| 3. `push Pointer_ObjectType` | `DesiredAccess` | 2do |
| 4. `push Pointer_ObjectType` | `&local_60` | 1ro |

### `_ACCESS_STATE _Stack_74` — el offset publicado coincide con el binario real

El Decompile pushea `&_Stack_74.PreviouslyGrantedAccess` como 1er argumento. El Listing lo calcula como `local_60` = `Stack[-0x60]` = `ebp-0x60`. Si `_Stack_74` (la struct completa) arranca en `ebp-0x74`, el campo `PreviouslyGrantedAccess` debería estar en offset `0x74-0x60 = 0x14` dentro de la struct. Contra el layout publicado en `NTDDK.H:6522`:

```
OperationID              0x00  (LUID, 8 bytes)
SecurityEvaluated        0x08
AuditHandleCreation      0x09
GenerateOnClose          0x0A
PrivilegesAllocated      0x0B
Flags                    0x0C  (4 bytes)
RemainingDesiredAccess   0x10  (4 bytes)
PreviouslyGrantedAccess  0x14  ← coincide exacto
```

**Confirmado en vivo:** con el breakpoint puesto antes de la llamada, `db ebp-60` mostró los 4 bytes en `0` — el buffer todavía sin inicializar, coherente con que `SeCreateAccessState` es quien lo llena.

### Manejo del resultado

```c
35  if (iVar1 < 0) {
36      return iVar1;
37  }
38  AccessState = (PACCESS_STATE)&_Stack_74.PreviouslyGrantedAccess;
```

Si `SeCreateAccessState` falla, el error se propaga directo como retorno de `ObOpenObjectByName`. Si no, `AccessState` (la variable local de `ObOpenObjectByName`, que venía `NULL`) pasa a apuntar al `_ACCESS_STATE` recién armado en el stack — se usa desde acá en adelante como si hubiera venido provisto desde afuera.

---

## 4. Captura de `ObjectAttributes`, `SecurityDescriptor`, y entrega a `ObpLookupObjectName`

Resto del cuerpo de la función, con las 4 llamadas restantes confirmadas por símbolo en `i386kd`:

```c
41  cVar3 = (char)((uint)local_8c >> 0x18);
42  iVar2 = func_0x80125cb6(AccessMode,ObjectAttributes,local_78,&local_80);
43  if (iVar2 < 0) goto joined_r0x80126054;
44  AccessState->SecurityDescriptor = (PSECURITY_DESCRIPTOR)0x0;
45  if (iStack_7c != 0) {
46    iVar2 = func_0x80176510(iStack_7c,AccessMode,1,0,&stack0xffffff64);
47    if (iVar2 < 0) goto joined_r0x80126054;
48    AccessState->SecurityDescriptor = unaff_ESI;
49  }
50  iVar2 = func_0x80125596(local_88,auStack_94,local_80,ObjectType,AccessMode,ObjectAttributes,
                             unaff_EDI,0,AccessState,&stack0xffffff5b,&stack0xffffff5c);
53  if (unaff_EDI != 0) {
54    func_0x801167f6(unaff_EDI);
55  }
```

### `func_0x80125cb6` = `ObpCaptureObjectAttributes`

```
80126006  e8abfcffff   call   NT!_ObpCaptureObjectAttributes (80125cb6)
```

Mismo rol que `ObpCaptureObjectAttributes`/probing ya visto en `IoCreateFile`, aplicado acá al propio `OBJECT_ATTRIBUTES`: si `AccessMode == UserMode`, probea que la struct y el `UNICODE_STRING` de `ObjectName` sean memoria de usermode válida, copia los campos a un buffer de confianza en modo kernel (mitigación TOCTOU — evita que otro thread modifique la memoria de usermode entre la validación y el uso), copia el nombre a pool paginado, y valida `Attributes` contra `OBJ_VALID_ATTRIBUTES`. Sus salidas (`local_78`, `local_80`, y muy probablemente `iStack_7c` — contiguo en el stack, `ebp-0x7c` al lado de `ebp-0x78`) alimentan el resto de la función.

### `func_0x80176510` = `SeCaptureSecurityDescriptor`

![kd: SeCaptureSecurityDescriptor y ObpLookupObjectName confirmados por símbolo](img/obopenobjectbyname-kd-securedescriptor-lookupobjectname-confirmed.png)

```
80126043  e8c8040500   call   NT!_SeCaptureSecurityDescriptor (80176510)
```

`iStack_7c` es candidato fuerte a ser el `SecurityDescriptor` capturado desde `ObjectAttributes` (por la salida contigua de `ObpCaptureObjectAttributes` y porque calza como 1er argumento de una función que "captura un security descriptor"). El `if (iStack_7c != 0)` solo entra si el caller pidió un `SecurityDescriptor` nuevo al abrir — en la corrida confirmada en vivo, `IoCreateFile` no pasó ninguno (`iStack_7c == 0`, confirmado con `db esp+3c`), así que la rama se saltea y `AccessState->SecurityDescriptor` queda en `NULL`.

### `func_0x80125596` = `ObpLookupObjectName` — la función principal

```
80126091  e800f5ffff   call   NT!_ObpLookupObjectName (80125596)
```

Acá es donde termina yendo todo lo que `ObOpenObjectByName` preparó hasta ahora: `ObjectAttributes` capturado, `AccessState` armado, `SecurityDescriptor` capturado si correspondía. Es la resolución real del objeto por nombre en el namespace del Object Manager — el próximo nivel de la pila a reversear.

### `func_0x801167f6` = `ExFreePool` — limpieza, no manejo de error

![kd: ExFreePool confirmado por símbolo](img/obopenobjectbyname-kd-exfreepool-cleanup-confirmed.png)

```
801260a4  e84d07ffff   call   NT!_ExFreePool (801167f6)
```

Libera `unaff_EDI` si se llegó a alocar algo (probablemente un buffer intermedio de `ObpCaptureObjectAttributes` o del propio lookup) — corre sin importar si `ObpLookupObjectName` tuvo éxito o falló, mismo patrón de epílogo ya visto en `IoCreateFile`.

### Resumen del flujo completo

1. `NULL`-check básico de `ObjectAttributes` → `STATUS_INVALID_PARAMETER` si falta.
2. `SeCreateAccessState` → arma el `AccessState` (si no vino provisto desde afuera).
3. `ObpCaptureObjectAttributes` → captura/valida `ObjectAttributes` de verdad.
4. Si el caller pidió `SecurityDescriptor` → `SeCaptureSecurityDescriptor` lo captura.
5. `ObpLookupObjectName` → resolución real del objeto por nombre.
6. `ExFreePool` de limpieza.

---

## 5. Cierre — `ObpCreateHandle` y limpieza final

Último tramo de la función, con las 4 llamadas restantes confirmadas por símbolo en `i386kd`:

![kd: ObpCreateHandle, ObDereferenceObject, ObpLeaveRootDirectoryMutex y SeDeleteAccessState confirmados por símbolo](img/obopenobjectbyname-kd-createhandle-cleanup-confirmed.png)

```
80126117  call   NT!_ObpCreateHandle (801246a6)
80126127  call   NT!_ObDereferenceObject (80113106)
80126135  call   NT!_ObpLeaveRootDirectoryMutex (80129966)
80126163  call   NT!_SeDeleteAccessState (80168700)
```

- **`ObpCreateHandle`** — el camino de éxito: convierte el objeto ya resuelto por `ObpLookupObjectName` en el `HANDLE` de salida que espera el caller original.
- **`ObDereferenceObject`** — camino de error después de `ObpCreateHandle`: si falla, decrementa el refcount del objeto ya referenciado por el lookup (patrón estándar de la API de NT).
- **`ObpLeaveRootDirectoryMutex`** — libera el mutex que protege el `RootDirectory` (`OBJECT_ATTRIBUTES`, Sección 1) mientras se resolvía el path, solo si se había tomado (`cVar3 != '\0'`).
- **`SeDeleteAccessState`** — contraparte de limpieza de `SeCreateAccessState` (Sección 3): libera el `ACCESS_STATE` armado en el stack si `ObOpenObjectByName` fue quien lo creó.

Con esto se cierra el reversing completo de `ObOpenObjectByName` — las 9 funciones internas del cuerpo (`SeCreateAccessState`, `ObpCaptureObjectAttributes`, `SeCaptureSecurityDescriptor`, `ObpLookupObjectName`, `ExFreePool`, `ObpCreateHandle`, `ObDereferenceObject`, `ObpLeaveRootDirectoryMutex`, `SeDeleteAccessState`) confirmadas por símbolo en `i386kd`.

**Próximo nivel de la pila:** `ObpLookupObjectName` — la resolución real del objeto por nombre en el namespace del Object Manager.

---

## Referencias

- NT DDK octubre 1994 — `ddk_extract/INC/NTDDK.H`, `NTDEF.H`, `NTSTATUS.H`
- `ntoskrnl.exe` build 3.10.5098.1 — base `0x80100000`
- Ghidra 11 — Decompile/Listing de `obopenobjectbyname.bin`
- `i386kd` — sesión de debug remoto entre `nt31-debugger.img` y `nt31.img` (serial TCP `4555`)
