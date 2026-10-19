# DGA: qué entrega hoy (MVP medido)

> Medido el 2026-10-18 sobre el commit `269b362`. El MVP no se ha diseñado: se ha **medido** ejecutando el
> proyecto en un entorno aislado (carpeta temporal fuera del repositorio, sin caché de bytecode, corpus NLTK
> descargado fuera de `~`). `git status` no ha cambiado tras las pruebas.
>
> **Entorno de verificación («entorno 2021»):** macOS en Apple Silicon, Python 3.9.6 **bajo emulación
> x86_64 (Rosetta)**, con las versiones exactas de `requirements.txt`. Es el único entorno en el que se ha
> conseguido ejecutar el detector (ver §0).
>
> Cada funcionalidad lleva su **criterio de aceptación** en forma de comando. «Verificado» quiere decir que se
> ejecutó y se observó ese resultado. El proyecto no tiene pruebas automáticas, así que ninguna
> funcionalidad tiene una prueba que la cubra.

---

## Qué es hoy

Hoy, DGA es un **laboratorio de terminal que funciona, pero solo en un entorno de 2021**. Quien consiga ese
entorno puede consultar 50 algoritmos DGA, generar sus dominios para cualquier fecha, buscar por fuerza bruta
la familia, la semilla y la posición de un dominio, y clasificar dominios como generados o humanos con el
modelo que viene incluido, que reproduce el ejemplo del README. Ya sirve para **estudiar y enseñar cómo
funcionan los DGA**. No sirve todavía para **demostrar cuánto acierta el detector**: no hay ninguna métrica
publicada, una de las evaluaciones está contaminada y la otra no se puede construir con las instrucciones
dadas. Tampoco se instala en un sistema actual tal como dice su documentación.

## 0. Condición previa: instalación

No es una funcionalidad, pero condiciona todas las demás.

| Comprobación | Resultado observado |
|---|---|
| `pip install -r requirements.txt`, Python 3.9.6 nativo arm64 | **Falla**: no existen binarios para `pandas==1.3.1`, `scikit-learn==0.24.2` ni `scipy==1.7.1`, y `pandas` no compila (`No module named 'pkg_resources'`) |
| Mismo comando bajo `arch -x86_64` (Rosetta) con `--only-binary :all:` | **Se instala** con las 14 versiones exactas |
| Cargar `ml-data/full.pkl` con Python 3.13.16 y scikit-learn 1.9.1 | **Falla**: `ValueError: node array from the pickle has an incompatible dtype` |
| Cargar `full-scaler.pkl` y `tranco.ng1` en ese mismo entorno moderno | Cargan |

**Consecuencia:** `lookdga.py` solo usa la biblioteca estándar. **Suposición:** funciona en cualquier
Python 3 actual (solo se ha probado en el entorno 2021). Todo lo que pasa por el modelo exige el entorno 2021.

---

## Funcionalidades que funcionan hoy

### 1. Listar las familias

`lookdga.py -L` muestra las 50 variantes con su nombre corto y su nombre largo.

- **Aceptación (verificado):** `python lookdga.py -L | wc -l` → `50`; la primera línea es
  `banjori              Banjori malware`.
- **Limitaciones:** ninguna observada.

### 2. Ficha de una familia

`lookdga.py -m <familia> -I` (o todas, sin `-m`) muestra referencias, descripción, regla YARA asociada,
periodo, semillas, tope por fecha, TLD y patrón.

- **Aceptación (verificado):** `python lookdga.py -m zloader -I` muestra 5 referencias, «Date affected: every
  day», «Max samples per date: 32» y «Domain regular expresion: [a-y]{20}.com».
- **Limitaciones:** los metadatos se escribieron a mano y no se han revisado. Hay al menos una incoherencia
  (suppobox dice «excepto el TLD .org» y su TLD es `.net`, `DGAs/suppobox.py:15-17`). La línea de la regla
  YARA solo da un nombre de fichero.
- **Casos límite:** un nombre de familia desconocido termina con «Unknown malware name» (`lookdga.py:70-74`).

### 3. Generar dominios

`lookdga.py -m <f> [-d AAAA-MM-DD] [-s semilla] -n N -G` imprime los N primeros dominios de cada familia.

- **Aceptación (verificado):**
  - `python lookdga.py -m tinba -n 5 -G` → `newstatinru.ru`, `justforyou0987.pw`, `phpsitegooddecoder.com`,
    `santaluable.com`, `santanyr.com`.
  - `python lookdga.py -n 3 -G` → 148 dominios: 3 de cada una de las 49 familias y 1 de tempedreve, cuyo tope
    por fecha es 1.
- **Limitaciones:**
  - La **fidelidad** solo tiene confirmación externa en **11 de 50** variantes, porque sus dominios aparecen en
    el feed de 360 Netlab (`ml-data/dga.dom`): simda, ramnit, banjori, shiotob, pykspa2, tinba, fobber1,
    fobber2, dircrypt, pizd, vawtrak3. De las otras 39 no hay ninguna prueba de que generen lo que genera el
    malware real.
  - Un fallo dentro de un generador se ignora en silencio (`dga.py:227`).
- **Casos límite:** si se pide más de lo que la familia genera por fecha, se recorta al tope sin avisar. Una
  fecha con formato incorrecto termina con un mensaje.

### 4. Crear un corpus etiquetado

`lookdga.py [-m …] [-d …] -n N -C` imprime `dominio,familia,semilla,fecha`, con N dominios por familia
repartidos entre semillas, y retrocede en fechas cuando la familia tiene tope.

- **Aceptación (verificado):** `python lookdga.py -n 100 -C` → 5.000 líneas de datos, 50 familias distintas.
- **Limitaciones:** la salida incluye **dos líneas de estado con códigos de color ANSI** (al principio y al
  final). Al redirigirla a un fichero, como manda el README, el CSV queda sucio. El propio
  `ml-data/mydgas.dom` las tiene.
- **Casos límite:** no elimina duplicados. `ml-data/mydgas.dom` tiene 504.000 líneas, pero solo 444.228
  dominios únicos.

### 5. Lista de bloqueo semanal

`lookdga.py [-n N] -F` imprime, sin repetidos, los dominios de todas las familias para hoy y los siete días
siguientes.

- **Aceptación (verificado):** `python lookdga.py -F` → 1.784 dominios, 0 repetidos.
- **Limitaciones:** el README no la menciona. Cubre ocho días, no siete, como dice su ayuda
  (`lookdga.py:46,102`). Con `-n` 10 por defecto, solo incluye los 10 primeros dominios de cada familia y
  día; para familias que generan cientos o miles al día, la lista es muy incompleta.

### 6. Sospecha por patrón

`lookdga.py -D dominio…` dice qué familias podrían haber generado cada dominio.

- **Aceptación (verificado):** `python lookdga.py -D google.com nvfowikhevmy.net` lista 13 familias para
  `nvfowikhevmy.net`, Tinba entre ellas.
- **Limitaciones: tasa de falsos positivos muy alta.** En esa misma ejecución, **`google.com` sale como
  posible DGA de 6 familias** (Nymaim, Proslikefan, Pykspa, Pykspa v2, Qsnatch A y B). Los patrones no
  escapan el punto del TLD ni se anclan al final (`dga.py:117-125`). Es un filtro previo para la fuerza
  bruta, no un veredicto.

### 7. Atribución por fuerza bruta

`lookdga.py -B dominio… [-d fecha] [-b días] [-n posiciones]` busca familia, semilla, día y posición.

- **Aceptación (verificado):** `python lookdga.py -B google.com nvfowikhevmy.net` → «Domain google.com not
  founded» y «tinba: Domain nvfowikhevmy.net with config 1 is in 10 position». Tarda **4 min 11 s** en el
  entorno 2021 (emulado).
- **Limitaciones:**
  - Por defecto solo explora las **10 primeras posiciones** de cada día y **366 días hacia atrás** desde hoy.
    Un dominio que esté más lejos sale «not founded» aunque la familia sea la correcta.
  - El coste crece con cada familia candidata, y por los falsos positivos de la función 6 hasta un dominio
    legítimo dispara búsquedas.
- **Casos límite:** si se pasa `-s`, se usa esa semilla en lugar de cada semilla conocida, pero el bucle
  repite igualmente una vez por cada semilla conocida (`dga.py:143-157`).

### 8. Detector con IA — *entregado con limitaciones*

`detectdga.py --check dominio…` clasifica cada dominio como «DGA generated» o «No DGA domain» con el modelo
incluido. Si sale DGA, añade las familias candidatas de la función 6.

- **Aceptación (verificado en el entorno 2021):** `python detectdga.py --check ughdnmmgdpscliraqnpl.com
  nvfowikhevmy.net uquslaigwaannie.ddns.net google.com facebook.com` → los tres primeros «DGA generated»,
  `google.com` y `facebook.com` «No DGA domain». Tarda 27 s, incluida la carga del modelo.
- **Limitaciones (todas observadas):**
  - **Solo funciona en el entorno 2021.** El modelo no carga en scikit-learn actual (§0).
  - **Desalineación de veredictos.** Cuando se descarta algún dominio de la lista, los veredictos se corren
    de dominio. `--check bbc.com google.com ughdnmmgdpscliraqnpl.com` imprime «No DGA» para `bbc.com` (es el
    de google), **«DGA generated» para `google.com`** (es el del tercero), y el tercero desaparece
    (`detectdga.py:650,709-710`).
  - **Descartes silenciosos.** No se evalúan los dominios con SLD de 3 letras o menos (`bbc.com`), los que
    empiezan por `www.`, los subdominios, los que tienen el TLD en mayúsculas (`GOOGLE.COM`) ni los que tienen
    un sufijo desconocido. No se avisa de ninguno.
  - **Si se descartan todos, se cae.** `--check bbc.com` → `ValueError: Found array with 0 sample(s)`.
  - **No se conoce su precisión.** El repositorio no contiene ninguna métrica.
  - El modelo se entrenó con dominios DGA de familias anteriores a 2021, y el 66 % de ellos son de solo dos
    familias (banjori y emotet).
- **Casos límite:** un dominio con comilla no rompe nada. Corrijo `docs/ESTUDIO.md`: el `eval` de `ngram.py`
  solo se alcanza con n-gramas que ya están en el diccionario, que no tienen comillas, así que el riesgo de
  inyección es teórico.

### 9. Detector y atribución encadenados — *entregado con limitaciones*

`detectdga.py -b --check dominio…` aplica, además, la fuerza bruta a los que salen DGA.

- **Aceptación (verificado en el entorno 2021):** el ejemplo del README con `-b` atribuye
  `nvfowikhevmy.net` a «tinba in 10 position». Tarda 1 min 51 s.
- **Limitaciones:**
  - **Dos de los tres dominios DGA del propio README salen «Not found by bruteforce».** Suposición: se
    generaron en 2021 y hoy quedan fuera de la ventana de 366 días. El ejemplo ya no da lo que promete.
  - Las 10 posiciones están fijas; no hay opción para cambiarlas (`detectdga.py:718`).
  - El informe pone fecha incluso para familias que no dependen de ella («for date 2026-10-18» en Tinba), y
    eso engaña.
  - Hereda todas las limitaciones de la función 8.

### 10. Estudio estadístico de las familias (menú `statsdga.py`)

Menú interactivo que se ejecuta con `python statsdga.py`.

- **Aceptación (verificado con 50 dominios por familia):**
  - opción 1 (tope por fecha): «dircrypt has a limit of 30 domains in a date»;
  - opción 2 (colisiones): «kraken2: 50 generated and 45 unique»;
  - opción 4 con Alexa (letras dobles): «1992 repeated 0 times (0.797)»;
  - opción 5 con DGA (letras repetidas);
  - opción 6 con Alexa (vocal/consonante);
  - opción 7 con DGA (dígitos);
  - opción 8 con Alexa y con DGA (sílabas): media de 2,46 frente a 3,87.
- **Corrijo `docs/ESTUDIO.md`:** la opción 2 no falla. El `IndexError` que se temía no ocurre, porque un
  duplicado siempre aparece antes de agotar la lista.
- **Limitaciones:**
  - Interactivo, sin parámetros por línea de órdenes ni salida reutilizable.
  - Los valores por defecto (10.000 a 50.000 por familia) hacen que cada opción tarde mucho.
  - La opción 3 (alfabeto y patrón sugerido) usa 50.000 dominios fijos por familia: **no se ha ejecutado**.
  - La opción 9 tiene un fallo de código en la rama Alexa (ver «A medias»).
- **Casos límite:** cualquier error se muestra como «Incorrect option» y vuelve al menú (`statsdga.py:567`).

---

## Métricas del modelo de 2021, medidas en 2026

Primera medición publicada del detector. Se hizo el 2026-10-19 en el entorno de 2021 (Python 3.9 x86_64,
`requirements.txt`), con el modelo `full.pkl` (SHA‑256 `922073c5…`) y `tiny.pkl` de `v2021`, el diccionario de
n-gramas de 2021 y la lista de sufijos de 2021, que son los recursos con los que se entrenó.

**Conjuntos de evaluación** (TODO.md, fase 4). Ninguno comparte dominio ni SLD con los datos de los que salió
el modelo (`tranco-main.dom`, `tranco-ngram.dom` y `dga.dom` de 2021). Lo comprueban `tests/test_datasets.py`
y el recuento guardado en `ml-data/<conjunto>.json`.

| Conjunto | Origen | Datos | Leídos | Excluidos (en el entrenamiento) | No evaluables | Evaluados |
|---|---|---|---:|---:|---:|---:|
| Secundario (`--secondary --set 2026`) | `tranco` (legítimos) | Tranco `467YX`, líneas 1.500.001–2.000.000 | 500.000 | 158.961 | 9.920 | 331.119 |
| | `own` (DGA) | `lookdga.py -d 2026-10-18 -n 3000 -C`, en UTC | 150.000 | 23.397 | 19.488 | 107.115 |
| | `hf` (DGA) | Hugging Face `harpomaxx/dga-detection`, revisión `26ab213` | 1.915.335 | 630.464 | 7.796 | 1.277.075 |
| Umbrella (`--umbrella`) | `umbrella` (legítimos) | Cisco Umbrella top 1M del 2026-10-17, reducido a 267.029 dominios registrables únicos | 267.029 | 135.029 | 12.223 | 119.840 |

«No evaluables» son los dominios que el detector descarta: SLD de 3 caracteres o menos, subdominio o sufijo
desconocido para la lista de 2021.

**Resultados:**

| Conjunto | Modelo | Exactitud | Falsos positivos en legítimos | DGA detectados (exhaustividad) | Precisión DGA |
|---|---|---:|---:|---:|---:|
| Secundario | `full` | 0,825 | 1,9 % (6.287 de 331.119) | 78,8 % (1.090.267 de 1.384.190) | 0,994 |
| Secundario | `tiny` | 0,623 | 6,1 % (20.077 de 331.119) | 54,7 % (757.668 de 1.384.190) | 0,974 |
| Umbrella | `full` | 0,892 | 10,8 % (12.963 de 119.840) | — | — |
| Umbrella | `tiny` | 0,896 | 10,4 % (12.479 de 119.840) | — | — |

Matrices de confusión (filas: real legítimo / DGA; columnas: predicho legítimo / DGA):

- secundario `full`: `[[324832, 6287], [293923, 1090267]]`;
- secundario `tiny`: `[[311042, 20077], [626522, 757668]]`;
- Umbrella `full`: `[[106877, 12963], [0, 0]]`;
- Umbrella `tiny`: `[[107361, 12479], [0, 0]]`.

Por origen, con `full` (con `tiny`): `tranco` acierta el 98,1 % (93,9 %), `own` el 72,8 % (48,0 %) y `hf` el
79,3 % (55,3 %).

**Por familia** (cálculo aparte con `full`, fuera de `detectdga.py`). Las familias que generan dominios a partir de
palabras casi no se detectan:
- generadores propios: `pizd` 0 %, `nymaim2` 0 %, `suppobox` 0,1 %, `qsnatcha` 0,1 %, `gozi` 1,8 %, `vawtrak3`
  5,8 %;
- Hugging Face: `volatile` 0 %, `suppobox` 0 %, `matsnu` 0,9 %, `pushdo` 13,4 %.

Las familias aritméticas, como `newgoz` o `zeus`, se detectan al 100 %.

**Cómo leerlo:**
- **La precisión DGA depende de la proporción del conjunto.** En el secundario hay 4 dominios DGA por cada
  legítimo. Para el uso real pesan más las tasas de falsos positivos en legítimos y de DGA detectados.
- **En Umbrella hay más de 5 veces más falsos positivos que en Tranco.** Umbrella mide consultas DNS, no
  visitas web, e incluye nombres de infraestructura (CDN, telemetría, servicios en la nube) que parecen
  aleatorios. Es el dato más cercano al tráfico de una red.
- **No hay dominios DGA reales posteriores a 2021.**
  - Los de Hugging Face son de 2016 o no tienen fecha.
  - Los propios salen de generadores reimplementados, de los que 39 de 50 no tienen confirmación externa.
  - El autor decidió no pedir acceso a DGArchive (2026-10-19).
  
  Estas cifras miden, por tanto, la generalización a dominios no vistos, no el envejecimiento del modelo
  ante familias nuevas.
- **La exclusión es estricta:** se quita cualquier dominio cuyo SLD aparezca en el entrenamiento, aunque
  tenga otro sufijo. Es la opción conservadora, porque 23 de las 24 características solo dependen del SLD.
- Las cifras de Alexa (`--test_alexa`) que se podían obtener antes no sirven: el 62 % de sus dominios estaba
  en el entrenamiento.

**Tiempos** (Apple Silicon bajo Rosetta): `--secondary --set 2026`, 34 min (2.565.335 dominios leídos);
`--umbrella`, 2 min; cada evaluación, entre 1 y 7 s.

## Implementado, no verificado

Estas funciones tienen código completo y se invocan desde la línea de órdenes, pero **no se han ejecutado en
este estudio** por su coste: horas de CPU (suposición) y cientos de MB. Hay **pruebas indirectas** de que se
ejecutaron en 2021, porque sus resultados están en el repositorio. No se cuentan como entregadas hasta
verificarlas.

| Función | Orden | Prueba indirecta |
|---|---|---|
| Crear el diccionario de n-gramas | `detectdga.py --ngram` | `ml-data/tranco.ng1-4` versionados |
| Crear el conjunto principal | `detectdga.py --main` | `full.pkl` existe, luego `main.pkl` existió; no se versionó |
| Entrenar una variante del modelo | `detectdga.py --train {full,ngram,nongram,nosyll,nongramnosyll,tiny}` | `full.pkl` y `tiny.pkl` versionados; del resto de variantes no hay rastro |
| Crear el conjunto Alexa | `detectdga.py --alexa` | ninguna |
| Estadística de alfabeto y patrón | `statsdga.py`, opción 3 | los patrones de las fichas pudieron salir de aquí (suposición) |

---

## A medias

| Qué | Estado | Cuánto falta | Dónde |
|---|---|---|---|
| **Conjunto secundario** (`--secondary`) | **Roto, verificado**: «Files ml-data/tranco-secondary.dom and/or ml-data/mydgas.dom not found» | Que la comprobación y la lectura usen el mismo fichero | `detectdga.py:775` vs `:356` |
| **Evaluar con el secundario** (`--test_secondary`) | Bloqueado por lo anterior | Lo anterior y verificar | `detectdga.py:584,802` |
| **Evaluar con Alexa** (`--test_alexa`) | El código está completo, pero la evaluación no es válida: 310.412 de 500.000 dominios están en el entrenamiento | Un conjunto de prueba independiente | `detectdga.py:584,809`; `ml-data/alexa.dom` |
| **Estadística de n-gramas** (`statsdga.py`, opción 9) | Con Alexa mide `1,google` en lugar de `google` (no separa el rango del CSV) | Separar el campo | `statsdga.py:260-272` |
| **Comprobación del diccionario** | Mira cuatro veces `tranco.ng1` | Comprobar ng1‑ng4 | `detectdga.py:730-731` |
| **Modo de reparto del corpus** | Solo funciona el modo por defecto; los otros dos fallarían | Definir la variable en todas las ramas | `dga.py:242-253` |

---

## Fuera de lo entregado

**Abandonado**

- **Comprobar por DNS si un dominio existe.** El código está (`detectdga.py:69-106`), pero nadie lo llama.
- **Modelo «tiny» en el detector.** Está versionado (55 MB), pero `--check` siempre usa `full`.

**Declarado y no implementado**

- **Reglas YARA.** Hay 35 reglas en `yara/` y el README dice que se extrajeron de Malpedia. El programa solo
  imprime su nombre de fichero (`dga.py:62-63`) y nunca las aplica a nada.

**Lo que la documentación promete y el código no cumple (verificado)**

| Promesa (README) | Realidad observada |
|---|---|
| «Python 3.7 o superior» con `pip install -r requirements.txt` | No se instala en Apple Silicon nativo; el modelo no carga en scikit-learn actual |
| Crear el conjunto secundario con `--secondary` | Falla siempre |
| `lookdga.py -C > ml-data/mydgas.dom` produce el CSV de prueba | Produce un CSV con líneas ANSI mezcladas |
| El ejemplo `-b --check` atribuye los dominios DGA | Hoy solo atribuye 1 de 3 |
| La sospecha por patrón «detecta» DGA | `google.com` sale como sospechoso de 6 familias |
| `statsdga.py` usa el «Alexa top million» | El fichero tiene 638.215 líneas |
| Se puede validar con Alexa | La validación está contaminada con datos de entrenamiento |

**Fuera por diseño** (ver «No objetivos» en `docs/IDEA.md`): no hay servicio, interfaz gráfica ni lectura de
registros de DNS o proxy, no se contacta con los dominios y no se hace reversing nuevo.

**Decidido para el futuro y no presente hoy:** entrada por fichero, exportación de resultados, métricas
publicadas, datos recientes y el flujo de muestra a dominios. Están en `docs/FUTURE.md`.

---

## Definición de terminado que el proyecto se dio

Deducida de lo que el repositorio mantiene de hecho:

- **Calidad:** «funciona en la máquina del autor con los datos del autor». Las versiones están fijadas, pero
  no la plataforma ni la versión de Python. No hay validación de entradas más allá de mensajes de error en
  la CLI.
- **Pruebas:** **ninguna**. No hay pruebas automáticas, vectores de referencia para los generadores, CI ni
  resultados de evaluación guardados.
- **Documentación:** un README con ejemplos de uso y las fuentes de datos, y referencias bibliográficas
  dentro de cada familia. No hay documentación de resultados, limitaciones ni decisiones.
- **Datos:** se versionan los resultados intermedios necesarios para usar el detector (diccionario, modelo,
  escaladores), pero no los conjuntos de características.

Es la definición de terminado propia de un trabajo académico entregado, no la de un producto mantenido. La
nueva definición la fija la etapa 1.1 de `docs/FUTURE.md`.
