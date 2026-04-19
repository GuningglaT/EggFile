# EggFile

EggFile es una aplicación peer-to-peer diseñada para compartir archivos de forma directa, simple y sin intermediarios.

La idea es eliminar la fricción típica de compartir contenido: no necesitás subir archivos a la nube ni configurar sistemas complejos. Solo elegís una carpeta de tu PC y decidís quién puede acceder.

---

## 📊 Comparativa

| Característica    | Nube (Google Drive, etc) | Apps P2P (Syncthing, etc)   | EggFile                  |
| ----------------- | ------------------------ | --------------------------- | ------------------------ |
| Transferencia     | Subida + descarga        | Sincronización constante    | Descarga directa         |
| Velocidad         | Limitada por servidor    | Buena, pero depende de sync | Directa (máxima posible) |
| Uso principal     | Almacenamiento           | Sincronizar carpetas        | Compartir archivos       |
| Configuración     | Media                    | Alta                        | Mínima                   |
| Control de acceso | Básico                   | Limitado                    | Granular                 |
| Persistencia      | Siempre en la nube       | Siempre sincronizado        | Solo cuando lo necesitás |
| Simplicidad       | Media                    | Baja                        | Alta                     |

---

## 🚀 Concepto

EggFile funciona bajo una lógica simple:

* Seleccionás una ruta local en tu PC
* Definís quién puede acceder
* Otros usuarios pueden explorar y descargar directamente desde tu máquina

Sin servidores centrales, sin almacenamiento externo, sin pasos innecesarios.

---

## 🧩 Características principales

| Feature                | Descripción                                          |
| ---------------------- | ---------------------------------------------------- |
| P2P directo            | Transferencias sin intermediarios                    |
| Control de acceso      | Elegís exactamente quién puede ver cada ruta         |
| Exploración remota     | Navegación de carpetas como si fueran locales        |
| Descarga por selección | Seleccionás múltiples archivos y se comprimen en ZIP |
| Cálculo en tiempo real | Tamaño total de descarga dinámico                    |
| Sistema de rutas       | Compartís carpetas completas, no archivos sueltos    |
| Sistema de familias    | Compartición grupal simplificada                     |
| Sin nube               | Todo ocurre entre usuarios                           |

---

## 👨‍👩‍👧 Sistema de Familias

EggFile incluye un sistema opcional de **familias** para simplificar el acceso.

En lugar de compartir rutas usuario por usuario:

* Creás una familia
* Agregás miembros
* Asignás rutas a esa familia

Todos los miembros automáticamente obtienen acceso.

### Estructura

| Elemento        | Descripción                           |
| --------------- | ------------------------------------- |
| Family          | Grupo de usuarios                     |
| memberIds       | IDs de usuarios dentro de la familia  |
| route.familyIds | Familias que tienen acceso a una ruta |

---

## 🔐 Control de acceso

Cada ruta tiene dos formas de definir acceso:

* Usuarios individuales (`allowedFriends`)
* Familias (`familyIds`)

### Resolución de acceso

```
Acceso final = allowedFriends + miembros de todas las familias
```

Esto permite:

* Control granular (usuarios individuales)
* Escalabilidad (familias)

---

## 🔄 Funcionamiento interno

### Endpoints principales

| Endpoint       | Función                       |
| -------------- | ----------------------------- |
| `/routes`      | Lista rutas disponibles       |
| `/browse`      | Navegar carpetas              |
| `/download`    | Descargar archivos o carpetas |
| `/folder-size` | Calcular tamaño total         |

Todos los endpoints validan acceso utilizando la resolución combinada de usuarios y familias.

---

## ⚙️ Arquitectura

| Componente   | Descripción                              |
| ------------ | ---------------------------------------- |
| Electron     | Aplicación de escritorio                 |
| IPC Handlers | Comunicación entre frontend y backend    |
| P2P Server   | Servidor local para compartir archivos   |
| DB local     | Persistencia de rutas, amigos y familias |

---

## 🧠 Filosofía

EggFile está diseñado con una premisa clara:

> Compartir archivos debería ser inmediato, directo y sin fricción.

No depende de servicios externos, no requiere almacenamiento intermedio y mantiene el control completamente del lado del usuario.

---

## 📌 Estado del proyecto

El proyecto se encuentra en desarrollo activo.

Funciones actuales:

* Sistema de rutas funcional
* Transferencias P2P operativas
* Control de acceso por usuario
* Sistema de familias implementado (backend)

Pendiente:

* Interfaz de usuario para familias
* Mejoras de experiencia de usuario
* Optimización general

---

## 📄 Licencia

[Definir licencia]
