# DGA: lo que está previsto

## Qué declara el propio proyecto

**El proyecto no declara ningún futuro en ninguna parte.** El repositorio no tiene roadmap, ni `TODO`,
`FIXME` o `XXX` en el código, ni comentarios del autor sobre trabajo pendiente. Tampoco hay issues ni pull
requests en GitHub (`gh issue list` y `gh pr list` sobre `dpgon/DGA`, consultados el 2026-10-18), y el último
push es del 2021-08-12.

Por tanto, cada entrada de este documento tiene uno de estos dos orígenes, y nunca se mezclan:

- **[deducido]**: sale del código o de su verificación (`docs/ESTUDIO.md`, `docs/MVP.md`).
- **[usuario]**: decisión del autor en la conversación de octubre de 2026, recogida en `docs/IDEA.md`.

Orden de etapas decidido por el usuario: **1.1 Puesta a punto → 1.2 Vigencia → 1.3 De la muestra a los
dominios.**

**Estado al 2026-10-19:** la corrección de versiones y datos de `docs/CORRECCIONES.md` (fases 1–5 de
`TODO.md`) cubre parte de la etapa 1.1. Cada apartado lo indica en una línea **Estado**; lo que no la tiene
sigue pendiente.

---

## 1.1 — Puesta a punto

**Tema:** que lo que ya existe se instale en un sistema actual, haga lo que dice y tenga cifras honestas.

**Criterio de etapa [usuario]:** reproducible y honesto. Cualquiera lo instala hoy, ejecuta los ejemplos
y obtiene métricas que se pueden reproducir, con sus límites documentados.

### 1.1.1 Instalación en sistemas actuales
- **Origen:** [deducido] fallo de instalación observado (`docs/MVP.md` §0); [usuario] plataformas Linux,
  macOS y Windows, sin conexión una vez instalado.
- **Aceptación:** con un Python con soporte vigente, en las tres plataformas, la instalación documentada
  termina sin errores y los ejemplos del README se ejecutan sin emulación. Tras instalar, ninguna orden
  necesita red.
- **Casos límite:** la primera ejecución no puede depender de descargas implícitas, como hoy el corpus de
  sílabas.
- **Estado (2026-10-20): hecho.** Se instala con `requirements-lock.txt` en Python 3.12 y 3.13 y
  `fetchdata.py --nltk` instala datos y corpus; ningún script descarga nada al ejecutarse (C1, C8, C11). Las
  pruebas pasan en la CI de Linux, macOS y Windows, y en un clon nuevo desde GitHub en macOS Apple Silicon.

### 1.1.2 Un modelo que cargue hoy
- **Origen:** [deducido] `full.pkl` no carga en scikit-learn actual (`docs/MVP.md` §0).
- **Aceptación:** el detector incluido carga y clasifica en el entorno de 1.1.1. Sus veredictos sobre un
  conjunto de referencia se publican junto al modelo.
- **Casos límite:** cargar un modelo descargado no debe exigir confiar a ciegas en un fichero ejecutable
  (principio «seguro de manejar», `docs/IDEA.md`).
- **Estado (2026-10-19): hecho.** Modelo reentrenado y guardado con skops, con metadatos y hashes; sus
  veredictos sobre la referencia de Netlab y sus métricas se publican con él (C2, `docs/MVP.md`). El modelo de
  2021 no se puede cargar en el entorno actual.

### 1.1.3 Veredictos fiables en el detector
- **Origen:** [deducido] desalineación, descartes silenciosos y caída con lista vacía, verificados
  (`docs/MVP.md` §8).
- **Aceptación:**
  - cada veredicto aparece siempre junto al dominio al que corresponde, en cualquier combinación de entradas;
  - cada dominio que no se evalúa aparece con su motivo;
  - una lista en la que no se evalúa nada no provoca un fallo;
  - mayúsculas, `www.` y subdominios tienen un tratamiento definido y documentado.
- **Estado (2026-10-19): hecho, salvo el último punto.** Veredictos alineados, descartes con motivo y lista
  vacía sin fallo (C12); las mayúsculas se pasan a minúsculas. `www.` y los subdominios no se evalúan y se dice
  por qué, pero su tratamiento sigue sin decidir.

### 1.1.4 Sospecha por patrón creíble
- **Origen:** [deducido] `google.com` sale como sospechoso de 6 familias (`docs/MVP.md` §6).
- **Aceptación:** sobre una muestra de dominios legítimos populares, la tasa de sospechas falsas se mide y
  se publica, y se reduce respecto a la actual. Los dominios del README `google.com` y `facebook.com` no
  salen como sospechosos.

### 1.1.5 Fuerza bruta con límites visibles y ajustables
- **Origen:** [deducido] ventana de 10 posiciones y 366 días; 2 de los 3 ejemplos del README no se atribuyen;
  fecha engañosa en familias sin fecha (`docs/MVP.md` §7 y §9); [usuario] límites claros y ajustables desde
  todas las vías de uso (`docs/IDEA.md`).
- **Aceptación:**
  - posiciones y días se pueden fijar también desde el detector;
  - el resultado «no encontrado» dice qué ventana se exploró;
  - en las familias que no dependen de la fecha no se informa de ninguna;
  - los ejemplos del README se atribuyen, o el README explica por qué no.

### 1.1.6 Conjuntos de evaluación independientes y métricas publicadas
- **Origen:** [deducido] `--secondary` roto; Alexa contaminada al 62 %; el 7 % del conjunto DGA secundario
  está en el de entrenamiento; ninguna métrica publicada (`docs/MVP.md` de 2026-10-18, «A medias»); [usuario] métricas
  honestas.
- **Aceptación:**
  - el conjunto secundario se construye siguiendo la documentación;
  - ningún conjunto de evaluación comparte dominios con el de entrenamiento, y se comprueba al construirlo;
  - el repositorio publica las métricas de cada variante del modelo, con el procedimiento para
    reproducirlas.
- **Casos límite:** sustituir Alexa, retirado en 2022, por una fuente legítima vigente.
- **Estado (2026-10-19): hecho para `full` y `tiny`, que se publican.** `--secondary` funciona (C6); los conjuntos excluyen
  los dominios y SLD del entrenamiento y lo comprueban al construirse (C5); Umbrella sustituye a Alexa (C3).
  Las métricas de los modelos de 2021 y 2026 están en `docs/MVP.md`. De las otras variantes, solo `ngram` se
  ha medido, en una prueba sin publicar.

### 1.1.7 Reproducir el entrenamiento completo
- **Origen:** [deducido] `--ngram`, `--main`, `--alexa`, `--train` y la opción 3 de estadísticas están sin
  verificar (`docs/MVP.md` de 2026-10-18, «Implementado, no verificado»).
- **Aceptación:** desde las fuentes documentadas, la cadena completa (diccionario → conjuntos → entrenamiento
  → evaluación) se ejecuta de principio a fin y da métricas iguales a las publicadas, dentro de un margen
  declarado. Se documenta cuánto tarda.
- **Estado (2026-10-19): hecho para `full`.** La cadena completa se ejecutó en la fase 5 (unos 11 minutos en
  Apple Silicon) y se repitió en un clon nuevo, con Python 3.13 en lugar de 3.12: el diccionario de n-gramas
  sale idéntico byte a byte, y `full` da las mismas matrices de confusión en las tres evaluaciones. Los
  ficheros `.skops` no son idénticos byte a byte (**suposición:** guardan datos variables, como fechas). La
  opción 3 de estadísticas sigue sin ejecutar.

### 1.1.8 Fidelidad de los generadores
- **Origen:** [deducido] solo 11 de 50 variantes tienen confirmación externa (`docs/MVP.md` §3); [usuario]
  comprobar que cada algoritmo reproduce su referencia (`docs/IDEA.md`).
- **Aceptación:** cada variante tiene al menos un caso de referencia (fecha, semilla y dominios esperados)
  tomado de una fuente externa, y se comprueba automáticamente. Las variantes sin referencia se señalan como
  no verificadas en su ficha.
- **Casos límite:** corregir los metadatos incoherentes (p. ej. el TLD de suppobox).

### 1.1.9 Reparar las piezas secundarias
- **Origen:** [usuario] conservarlo todo y repararlo (`docs/IDEA.md`); [deducido] fallos concretos.
- **Aceptación:**
  - `-C` produce un CSV limpio al redirigirlo;
  - `-F` cubre los días que anuncia y su alcance por familia está documentado;
  - la opción 9 de estadísticas mide bien los dominios legítimos;
  - todos los modos de reparto del corpus funcionan;
  - el menú de estadísticas se puede usar también sin interacción;
  - un fallo de un generador se informa en lugar de perderse.
- **Estado (2026-10-19): solo el primer punto.** `-C` produce un CSV limpio (C13). El resto sigue pendiente.

### 1.1.10 Decidir el destino de lo abandonado
- **Origen:** [deducido] comprobación DNS sin uso y modelo «tiny» sin uso en el detector; [usuario]
  conservar y reparar, sin contactar con los dominios analizados (`docs/IDEA.md`, «No objetivos»).
- **Aceptación:**
  - el modelo «tiny» se puede elegir en el detector, o su papel queda documentado como variante de estudio;
  - la comprobación DNS se retira, porque contradice el no objetivo «no contacta con los dominios
    analizados», o pasa a ser opcional, explícita y documentada. **Pendiente de decidir** (ver ideas
    aparcadas).

### 1.1.11 Pruebas y documentación como definición de terminado
- **Origen:** [deducido] cero pruebas y ninguna documentación de resultados (`docs/MVP.md`, «Definición de
  terminado»); [usuario] «funciona hoy, tal como dice».
- **Aceptación:**
  - cada funcionalidad de `docs/MVP.md` tiene una prueba automática que comprueba su criterio de aceptación;
  - las pruebas pasan en las tres plataformas;
  - el README coincide con el comportamiento y declara las limitaciones conocidas.
- **Estado (2026-10-20): en parte.** Hay pruebas automáticas de caracterización y de cada corrección, y la CI
  pasa en las tres plataformas. No todas las funcionalidades tienen una
  prueba de su criterio de aceptación (por ejemplo, las opciones 4-9 de estadísticas).

---

## 1.2 — Vigencia

**Tema:** demostrar con datos actuales si el enfoque sigue sirviendo, y hacerlo práctico para listas reales.

### 1.2.1 Dominios DGA recientes como datos
- **Origen:** [usuario] los datos recientes entran como datos de entrenamiento y evaluación (`docs/IDEA.md`).
- **Aceptación:** el proyecto documenta una o varias fuentes públicas vigentes de dominios DGA posteriores a
  2021 y un procedimiento reproducible para incorporarlos. Se indica qué familias y qué periodo cubren.
- **Casos límite:** fuentes discontinuadas. Hay que comprobar si el feed de 360 Netlab sigue vivo.
- **Estado (2026-10-19):** el feed de 360 Netlab ya no responde. Se evalúa con el dataset de Hugging Face
  `harpomaxx/dga-detection`, pero sus dominios son de 2016 o no tienen fecha, así que **no hay datos DGA reales
  posteriores a 2021**. El autor decidió **no pedir acceso a DGArchive** por ahora (2026-10-19).

### 1.2.2 Medir el envejecimiento del modelo de 2021
- **Origen:** [usuario] medir cuánto ha envejecido.
- **Aceptación:** se publica la comparación del modelo de 2021 (tras 1.1.2) sobre datos de 2021 y sobre
  datos recientes, por familia, con las mismas métricas que en 1.1.6.

### 1.2.3 Modelo reentrenado con datos actuales
- **Origen:** [usuario] entrenar con datos recientes.
- **Aceptación:** existe un modelo entrenado con datos que incluyen los recientes. Sus métricas, sobre
  conjuntos independientes, se publican junto a las del de 2021, y el usuario puede elegir cualquiera de los
  dos.
- **Casos límite:** que una o dos familias no dominen el entrenamiento, como hoy banjori y emotet (66 %).
- **Estado (2026-10-19): en parte.** El modelo de 2026 se entrenó con dominios legítimos de 2026, pero con
  los mismos dominios DGA de 2021, a falta de otros (1.2.1). El de 2021 solo se puede usar en su entorno
  (etiqueta `v2021`), no elegir desde el actual.

### 1.2.4 Generadores de familias recientes con algoritmo publicado
- **Origen:** [usuario] solo cuando el algoritmo ya esté publicado por terceros.
- **Aceptación:** cada familia añadida trae su referencia pública, su ficha completa y su caso de
  referencia (como en 1.1.8).

### 1.2.5 Entrada por fichero o lista
- **Origen:** [usuario] (`docs/IDEA.md`, Funcionalidad 3).
- **Aceptación:** el detector, la sospecha por patrón y la fuerza bruta aceptan un fichero con un dominio por
  línea, además de los argumentos. Las líneas vacías o inválidas se informan sin detener el análisis.
- **Casos límite:** listas de decenas de miles de dominios. Se documenta el tiempo esperado, sobre todo con
  fuerza bruta.

### 1.2.6 Exportación de resultados
- **Origen:** [usuario] (`docs/IDEA.md`, recorrido A).
- **Aceptación:** los resultados se pueden guardar en un formato tabular estándar, sin códigos de color, con
  una fila por dominio: dominio, veredicto, motivo si no se evaluó, familias candidatas y atribución.

---

## 1.3 — De la muestra a los dominios

**Tema:** cerrar el camino entre un binario sospechoso y la lista de dominios que hay que bloquear.

### 1.3.1 Identificar la familia de una muestra
- **Origen:** [usuario] uso real de las reglas YARA (`docs/IDEA.md`, Funcionalidad 5); [deducido] 35 reglas
  presentes y sin uso.
- **Aceptación:** dado un fichero, el laboratorio indica qué familias del catálogo reconoce y con qué
  regla, **sin ejecutarlo**. Si no reconoce ninguna, lo dice.
- **Casos límite:**
  - cuatro variantes no tienen regla (fosniw, pizd, proslikefan, sisron) y deben aparecer así en su ficha;
  - algunas reglas sirven para varias variantes (p. ej. locky2/locky3);
  - funcionar sin conexión en máquinas de análisis aisladas.

### 1.3.2 De la familia identificada a sus dominios
- **Origen:** [usuario] (`docs/IDEA.md`, recorrido D).
- **Aceptación:** tras identificar la familia, el usuario obtiene su ficha y sus dominios para la fecha que
  elija, en el mismo flujo, y puede exportarlos como en 1.2.6.

### 1.3.3 Reglas al día
- **Origen:** [deducido] las reglas son de junio de 2021 (cabeceras de `yara/*.yar`).
- **Aceptación:** se documenta de dónde y cuándo se obtuvieron, y el procedimiento para actualizarlas
  respetando su licencia (CC BY‑SA 4.0).

---

## Ideas aparcadas

- **Comprobación DNS opcional.** [deducido] Saber si un dominio generado está registrado tiene valor docente,
  pero choca con un no objetivo. Hay que decidir en 1.1.10 si se retira o queda como opción explícita.
- **Biblioteca reutilizable.** Se propuso como forma de uso y no se eligió (`docs/IDEA.md`, plataformas). Se
  recuerda por si otros quieren integrar el catálogo.
- **Demo web o interfaz gráfica.** No es objetivo hoy, pero ayudaría a quien llega desde GitHub.
- **Lectura de registros de DNS o proxy.** No es objetivo; sería el paso siguiente a la entrada por fichero.
- **Compatibilidad de licencias.** GPL v2 del proyecto, CC BY‑SA 4.0 de las reglas y la licencia de los
  algoritmos de origen. No es una funcionalidad, pero conviene revisarlo antes de publicar 1.1. Las licencias
  de los datos ya están revisadas en `ml-data/MANIFEST` (2026-10-19); las de las reglas y los algoritmos, no.
- **Peso del repositorio.** 367 MB de datos versionados, con `full.pkl` a 100 KB del límite de GitHub.
  Pertenece a la arquitectura, pero afecta a la experiencia de quien clona. **Resuelto en 2026** (C8): los
  datos son assets de release; siguen en el historial de git.
