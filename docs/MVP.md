# DGA: qué entrega hoy (MVP medido)

> **Medido de nuevo el 2026-10-19** sobre el commit `96e4046`, tras la puesta a punto de las fases 1–5 de
> `TODO.md`. Igual que la primera vez, el MVP no se ha diseñado: se ha **medido** ejecutando el proyecto en un
> clon nuevo, fuera del repositorio de trabajo, con los datos instalados por `fetchdata.py` y el corpus NLTK
> fuera de `~`.
>
> **Entorno de verificación («entorno 2026»):** macOS en Apple Silicon, Python 3.12.15 **nativo** (sin
> Rosetta), con las versiones exactas de `requirements-lock.txt`. Las pruebas automáticas pasan además con
> Python 3.13.16 en el mismo Mac y con 3.12 y 3.13 en Linux (`act`). Windows no se ha probado.
>
> Cada funcionalidad lleva su **criterio de aceptación** en forma de comando. «Verificado» quiere decir que se
> ejecutó y se observó ese resultado. Desde la fase 1 hay pruebas automáticas (`tests/`): se indica cuál cubre
> cada criterio. Los comandos con `-G`, `-C` o `-F` dependen de la fecha y la hora; las cifras de esos
> criterios se tomaron con `-d 2026-10-18` y `TZ=UTC`, como en las pruebas.
>
> **La primera medición** (2026-10-18, commit `269b362`) se hizo en el **entorno 2021**: Python 3.9.6 bajo
> emulación x86_64 (Rosetta) con las versiones exactas de 2021, el único en el que entonces funcionaba el
> detector. Lo que cambió desde entonces se indica en cada sección como «Antes (2026-10-18)».

---

## Qué es hoy

Hoy, DGA es un **laboratorio de terminal que se instala con un Python actual**. Permite:
- consultar 50 algoritmos DGA y generar sus dominios para cualquier fecha;
- buscar por fuerza bruta la familia, la semilla y la posición de un dominio;
- clasificar dominios como generados o humanos con un modelo reentrenado con datos de 2026, que reproduce el
  ejemplo del README.

Sirve para **estudiar y enseñar cómo funcionan los DGA**, y ya se puede **saber cuánto acierta el detector**:
hay métricas medidas sobre conjuntos que no comparten ningún dominio con el entrenamiento. Esas métricas
muestran sus límites:
- no detecta los DGA que forman dominios con palabras;
- marca como DGA muchos nombres aleatorios de CDN;
- no hay dominios DGA reales posteriores a 2021 con los que medir cómo envejece.

## 0. Condición previa: instalación

No es una funcionalidad, pero condiciona todas las demás.

| Comprobación (entorno 2026) | Resultado observado |
|---|---|
| `pip install -r requirements-lock.txt -r requirements-dev.txt`, Python 3.12.15 nativo arm64, entorno nuevo | **Se instala** |
| `python fetchdata.py --from <release/model-2026>` en un clon nuevo | Copia los 10 ficheros del modelo y descarga de su origen los de Tranco y Umbrella; los 2 ficheros de `data-2026` dan 404 porque esa release **aún no está publicada** (fase 7) |
| `python fetchdata.py --from <release/data-2026>` a continuación | «All files installed and verified» |
| `detectdga.py --check …` | Funciona: el modelo `.skops` carga en scikit-learn 1.9.1 |

**Antes (2026-10-18):**
- `pip install -r requirements.txt` fallaba en Python 3.9.6 nativo arm64, porque no había binarios para
  `pandas==1.3.1`, `scikit-learn==0.24.2` ni `scipy==1.7.1`;
- solo se instalaba bajo `arch -x86_64` (Rosetta), con `--only-binary :all:`;
- `full.pkl` no cargaba en scikit-learn 1.9.1 (`ValueError: node array from the pickle has an incompatible
  dtype`).

Ese entorno sigue en la etiqueta `v2021`, y sus datos se instalan con `python fetchdata.py --set 2021`.

**Pruebas:** `tests/test_fetchdata.py` (descarga y verificación) y `tests/test_data.py` (ficheros instalados
frente al manifiesto).

---

## Funcionalidades que funcionan hoy

### 1. Listar las familias

`lookdga.py -L` muestra las 50 variantes con su nombre corto y su nombre largo.

- **Aceptación (verificado):** `python lookdga.py -L | wc -l` → `50`; la primera línea es
  `banjori              Banjori malware`.
- **Limitaciones:** ninguna observada.
- **Pruebas:** `tests/test_lookdga.py`.

### 2. Ficha de una familia

`lookdga.py -m <familia> -I` (o todas, sin `-m`) muestra referencias, descripción, regla YARA asociada,
periodo, semillas, tope por fecha, TLD y patrón.

- **Aceptación (verificado):** `python lookdga.py -m zloader -I` muestra «Date affected: every day», «Max
  samples per date: 32» y «Domain regular expresion: [a-y]{20}.com».
- **Limitaciones:** los metadatos se escribieron a mano y no se han revisado. Hay al menos una incoherencia
  (suppobox dice «excepto el TLD .org» y su TLD es `.net`, `DGAs/suppobox.py:15-17`). La línea de la regla
  YARA solo da un nombre de fichero.
- **Casos límite:** un nombre de familia desconocido termina con «Unknown malware name».
- **Pruebas:** `tests/test_lookdga.py`.

### 3. Generar dominios

`lookdga.py -m <f> [-d AAAA-MM-DD] [-s semilla] -n N -G` imprime los N primeros dominios de cada familia.

- **Aceptación (verificado):**
  - `python lookdga.py -m tinba -n 5 -G` → `newstatinru.ru`, `justforyou0987.pw`, `phpsitegooddecoder.com`,
    `santaluable.com`, `santanyr.com`.
  - `python lookdga.py -n 3 -G` → 148 dominios: 3 de cada una de las 49 familias y 1 de tempedreve, cuyo tope
    por fecha es 1.
  - Los 3 primeros dominios de cada familia, configuración y semilla para 2026-10-18 son idénticos en el
    entorno 2021 y en el 2026 (`tests/data/snapshot_2026-10-18.csv`).
- **Limitaciones:**
  - La **fidelidad** solo tiene confirmación externa en **11 de 50** variantes, porque sus dominios aparecen en
    el feed de 360 Netlab (`ml-data/dga.dom`): simda, ramnit, banjori, shiotob, pykspa2, tinba, fobber1,
    fobber2, dircrypt, pizd, vawtrak3. De las otras 39 no hay ninguna prueba de que generen lo que genera el
    malware real.
  - Un fallo dentro de un generador se ignora en silencio (`dga.py`, `except:` desnudo en `create`).
  - **Sin `-d`, la fecha incluye la hora actual**, y pizd, pykspa2 y suppobox generan dominios distintos según
    la hora del día. pykspa2 y suppobox dependen además de la zona horaria de la máquina, porque usan
    `time.mktime` (`docs/CORRECCIONES.md`, anexo).
- **Casos límite:** si se pide más de lo que la familia genera por fecha, se recorta al tope sin avisar. Una
  fecha con formato incorrecto termina con un mensaje.
- **Pruebas:** `tests/test_generators.py` (instantánea y referencia de Netlab), `tests/test_lookdga.py`.

### 4. Crear un corpus etiquetado

`lookdga.py [-m …] [-d …] -n N -C` imprime `dominio,familia,semilla,fecha`, con N dominios por familia
repartidos entre semillas, y retrocede en fechas cuando la familia tiene tope.

- **Aceptación (verificado):** `python lookdga.py -d 2026-10-18 -n 100 -C > corpus.csv` → 5.000 líneas, 50
  familias distintas, ninguna línea con códigos ANSI.
- **Limitaciones:** solo funciona el modo de reparto por defecto (ver «A medias»).
- **Casos límite:** no elimina duplicados. El `ml-data/mydgas.dom` de 2021 tiene 504.000 líneas, pero solo
  444.228 dominios únicos.
- **Antes (2026-10-18):** la salida mezclaba dos líneas de estado con códigos ANSI con el CSV, y el
  `mydgas.dom` de 2021 las tiene. Desde la fase 2 (C13) van a la salida de error.
- **Pruebas:** `tests/test_lookdga.py`.

### 5. Lista de bloqueo semanal

`lookdga.py [-n N] -F` imprime, sin repetidos, los dominios de todas las familias para hoy y los siete días
siguientes.

- **Aceptación (verificado):** `TZ=UTC python lookdga.py -d 2026-10-18 -F` → 1.784 dominios, 0 repetidos. Con
  la zona horaria de Madrid salen 1.794 (ver §3).
- **Limitaciones:** cubre ocho días, no siete, como dice su ayuda (`lookdga.py:45`). Con `-n` 10 por defecto,
  solo incluye los 10 primeros dominios de cada familia y día; para familias que generan cientos o miles al
  día, la lista es muy incompleta.
- **Pruebas:** `tests/test_lookdga.py`.

### 6. Sospecha por patrón

`lookdga.py -D dominio…` dice qué familias podrían haber generado cada dominio.

- **Aceptación (verificado):** `python lookdga.py -D google.com nvfowikhevmy.net` lista 13 familias para
  `nvfowikhevmy.net`, Tinba entre ellas.
- **Limitaciones: tasa de falsos positivos muy alta.** En esa misma ejecución, **`google.com` sale como
  posible DGA de 6 familias** (Nymaim, Proslikefan, Pykspa, Pykspa v2, Qsnatch A y B). Los patrones no
  escapan el punto del TLD ni se anclan al final (`dga.py:117-125`). Es un filtro previo para la fuerza
  bruta, no un veredicto.
- **Pruebas:** `tests/test_lookdga.py`.

### 7. Atribución por fuerza bruta

`lookdga.py -B dominio… [-d fecha] [-b días] [-n posiciones]` busca familia, semilla, día y posición.

- **Aceptación (verificado):** `python lookdga.py -B google.com nvfowikhevmy.net` → «Domain google.com not
  founded» y «tinba: Domain nvfowikhevmy.net with config 1 is in 10 position». Tarda **1 min 45 s** (en el
  entorno 2021, bajo emulación, tardaba 4 min 11 s).
- **Limitaciones:**
  - Por defecto solo explora las **10 primeras posiciones** de cada día y **366 días hacia atrás** desde hoy.
    Un dominio que esté más lejos sale «not founded» aunque la familia sea la correcta.
  - El coste crece con cada familia candidata, y por los falsos positivos de la función 6 hasta un dominio
    legítimo dispara búsquedas.
- **Casos límite:** si se pasa `-s`, se usa esa semilla en lugar de cada semilla conocida, pero el bucle
  repite igualmente una vez por cada semilla conocida (`dga.py:143-157`).
- **Pruebas:** `tests/test_lookdga.py` (`slow`).

### 8. Detector con IA — *entregado con limitaciones*

`detectdga.py --check dominio…` clasifica cada dominio como «DGA generated» o «No DGA domain» con el modelo
de 2026 (`ml-data/full.skops`). Si sale DGA, añade las familias candidatas de la función 6.

- **Aceptación (verificado):**
  - `python detectdga.py --check ughdnmmgdpscliraqnpl.com nvfowikhevmy.net uquslaigwaannie.ddns.net
    google.com facebook.com` → los tres primeros «DGA generated», `google.com` y `facebook.com` «No DGA
    domain», como con el modelo de 2021. Tarda 3,7 s, incluida la carga del modelo (27 s en el entorno 2021).
  - `wikipedia.org` → «No DGA domain».
  - De los 188 dominios de `tests/data/referencia_netlab.csv`, 172 salen «DGA generated». Están en el
    entrenamiento, así que es una comprobación de cordura, no una métrica.
  - `--check bbc.com google.com ughdnmmgdpscliraqnpl.com GOOGLE.COM www.google.com example.notasuffix` → cada
    veredicto junto a su dominio; `GOOGLE.COM` se evalúa en minúsculas; `bbc.com`, `www.google.com` y
    `example.notasuffix` salen en «Not evaluated» con su motivo.
  - `--check bbc.com` → «Not evaluated», sin error.
  - El modelo no carga si su diccionario de n-gramas, su lista de sufijos o su escalador no coinciden con los
    SHA‑256 de `ml-data/full.json`, y dice cuál falla.
- **Limitaciones:**
  - **Precisión limitada y conocida:** ver «Métricas del detector». Las familias de palabras casi no se
    detectan, y los nombres aleatorios de CDN (`*.cloudfront.net`) salen como DGA.
  - Solo evalúa dominios registrables: los subdominios y los prefijos `www.` no se evalúan (`docs/FUTURE.md`
    1.1.3).
  - Entrena con dominios DGA de familias anteriores a 2021, y el 66 % de ellos son de solo dos familias
    (banjori y emotet). No hay datos DGA reales más recientes.
- **Antes (2026-10-18):** el modelo solo cargaba en el entorno 2021; cuando se descartaba un dominio, los
  veredictos se corrían de dominio (`google.com` salía «DGA generated»); los descartes eran silenciosos;
  `--check bbc.com` se caía con `ValueError`, y no había ninguna métrica. Lo corrigieron C12 (fase 2) y C2
  (fase 5).
- **Pruebas:** `tests/test_check.py`, `tests/test_model.py`.

### 9. Detector y atribución encadenados — *entregado con limitaciones*

`detectdga.py -b --check dominio…` aplica, además, la fuerza bruta a los que salen DGA.

- **Aceptación (verificado):** el ejemplo del README con `-b` atribuye `nvfowikhevmy.net` a «tinba in 10
  position». Tarda 58 s (1 min 51 s en el entorno 2021).
- **Limitaciones:**
  - **Dos de los tres dominios DGA del propio README salen «Not found by bruteforce».** Suposición: se
    generaron en 2021 y hoy quedan fuera de la ventana de 366 días. El README lo explica.
  - Las 10 posiciones están fijas; no hay opción para cambiarlas.
  - El informe pone fecha incluso para familias que no dependen de ella («for date 2026-10-19» en Tinba), y
    eso engaña.
  - Hereda todas las limitaciones de la función 8.
- **Pruebas:** `tests/test_check.py` (`slow`).

### 10. Estudio estadístico de las familias (menú `statsdga.py`)

Menú interactivo que se ejecuta con `python statsdga.py`. Los dominios reales salen ahora de la lista Tranco
del juego 2026 (`ml-data/tranco.csv`), no de Alexa.

- **Aceptación (verificado con 50 dominios por familia):**
  - opción 1 (tope por fecha): «dircrypt has a limit of 30 domains in a date»;
  - opción 2 (colisiones): «kraken2: 50 generated and 45 unique»;
  - opción 4 con Tranco (letras dobles): «2042 repeated 0 times (0.817)», sobre 2.500 dominios;
  - opción 8 con Tranco y con DGA (sílabas): media de 2,646 frente a 3,858.
- **Limitaciones:**
  - Interactivo, sin parámetros por línea de órdenes ni salida reutilizable.
  - Los valores por defecto (10.000 a 50.000 por familia) hacen que cada opción tarde mucho.
  - La opción 3 (alfabeto y patrón sugerido) usa 50.000 dominios fijos por familia: **no se ha ejecutado**.
  - La opción 9 tiene un fallo de código en la rama de dominios reales (ver «A medias»).
- **Casos límite:** cualquier error se muestra como «Incorrect option» y vuelve al menú.
- **Antes (2026-10-18):** usaba la copia de Alexa de 2021, de 638.215 dominios; con ella, la opción 4 daba
  «1992 repeated 0 times (0.797)» y la opción 8 una media de 2,46.
- **Pruebas:** `tests/test_statsdga.py`.

---

## Métricas del detector

Medidas sobre conjuntos que no comparten ningún dominio ni SLD con los datos de entrenamiento de cada modelo
(C5). Primero las del modelo actual y, para comparar, las del de 2021.

### Modelo de 2026

Modelo reentrenado en la fase 5 de `TODO.md` el 2026-10-19, en Python 3.13.16 nativo (Apple Silicon) con las
versiones de `requirements-lock.txt` (scikit-learn 1.9.1). Mismos hiperparámetros que en 2021 (30 árboles,
`min_samples_leaf=5`, `random_state=1`); cambian los datos:
- diccionario de n-gramas: `ml-data/2026/tranco-ngram.dom` (Tranco `467YX`, 2.595.070 dominios);
- legítimos de entrenamiento: `ml-data/2026/tranco-main.dom` (Tranco `467YX`, líneas 1–1.500.000);
- DGA de entrenamiento: `dga.dom` de 2021 (360 Netlab), el mismo que entonces, porque no hay otro;
- lista de sufijos: la de Mozilla del 2026-10-17, en lugar de la de 2021.

Los metadatos (`ml-data/full.json`, `tiny.json`) guardan las versiones, los SHA‑256 de todo lo anterior, los
hiperparámetros y estas métricas.

**Conjuntos de evaluación**, construidos igual que en la fase 4 pero excluyendo los datos de entrenamiento de
2026:

| Conjunto | Origen | Leídos | Excluidos (en el entrenamiento) | No evaluables | Evaluados |
|---|---|---:|---:|---:|---:|
| Secundario (`--secondary`) | `tranco` (legítimos) | 500.000 | 75.534 | 9.821 | 414.645 |
| | `own` (DGA) | 150.000 | 23.390 | 19.501 | 107.109 |
| | `hf` (DGA) | 1.915.335 | 630.466 | 7.796 | 1.277.073 |
| Umbrella (`--umbrella`) | `umbrella` (legítimos) | 275.443 | 232.888 | 12.925 | 29.681 |

En Umbrella se excluyen muchos más dominios que en la fase 4: Tranco y Umbrella de octubre de 2026 coinciden
mucho, y el entrenamiento de 2026 cubre casi toda la lista Tranco: líneas 1–1.500.000 (`main`) y
2.000.001–4.595.070 (`ngram`). Con la lista de
sufijos nueva hay 275.443 dominios registrables únicos, frente a 267.029.

**Resultados**, con los de 2021 (fase 4) para comparar:

| Conjunto | Modelo | Exactitud | Falsos positivos en legítimos | DGA detectados | Precisión DGA | 2021: FP / detectados |
|---|---|---:|---:|---:|---:|---:|
| Secundario | `full` | 0,836 | 1,2 % (4.844 de 414.645) | 79,0 % (1.093.402 de 1.384.182) | 0,996 | 1,9 % / 78,8 % |
| Secundario | `tiny` | 0,646 | 8,2 % (34.105 de 414.645) | 56,4 % (780.990 de 1.384.182) | 0,958 | 6,1 % / 54,7 % |
| Umbrella | `full` | 0,632 | 36,8 % (10.935 de 29.681) | — | — | 10,8 % / — |
| Umbrella | `tiny` | 0,807 | 19,3 % (5.714 de 29.681) | — | — | 10,4 % / — |

Matrices de confusión (filas: real legítimo / DGA; columnas: predicho legítimo / DGA):
- secundario `full`: `[[409801, 4844], [290780, 1093402]]`;
- secundario `tiny`: `[[380540, 34105], [603192, 780990]]`;
- Umbrella `full`: `[[18746, 10935], [0, 0]]`;
- Umbrella `tiny`: `[[23967, 5714], [0, 0]]`.

Por origen, con `full` (con `tiny`): `tranco` acierta el 98,8 % (91,8 %), `own` el 71,9 % (48,4 %) y `hf` el
79,6 % (57,1 %). En la partición de prueba de `--train` (20 % de `main.pkl`, no independiente), `full` da 0,986
y `tiny` 0,936.

**Por familia**, con `full`: las de palabras siguen sin detectarse (`pizd` 0 %, `nymaim2` 0 %, `suppobox`
0,1 %, `volatile` 0,1 %, `matsnu` 2,3 %, `gozi` 3,8 %); las aritméticas, como `newgoz` o `zeus`, al 100 %.

**Cómo leerlo:**
- **En el secundario, `full` iguala o mejora al de 2021:** menos falsos positivos (1,2 % frente a 1,9 %) y los
  mismos DGA detectados. `tiny` da más falsos positivos (8,2 % frente a 6,1 %).
- **La subida de falsos positivos en Umbrella no es del modelo, sino del conjunto.** Lo comprobé así:
  - sobre los 21.140 dominios que están en los dos conjuntos Umbrella (el de la fase 4 y este), el modelo de
    2021 marca el 45,1 % y el de 2026 el 44,2 %;
  - los 98.700 dominios que solo estaban en el de la fase 4 (los que ahora se excluyen por estar en el Tranco
    de 2026) daban un 3,5 % de falsos positivos con el modelo de 2021;
  - lo que queda son sobre todo nombres de infraestructura aleatorios: 8.857 de los 10.935 falsos positivos
    son de `cloudfront.net` (por ejemplo `d3lnoy3aplwg2k.cloudfront.net`), y le siguen `trafficmanager.net`,
    `execute-api.*.amazonaws.com` y `akamaihd.net`. La lista de sufijos los trata como dominios registrables;
  - con sufijos de una etiqueta (`.com`, `.net`…), el modelo marca el 2,3 % (4.710 dominios); sin
    `cloudfront.net` ni `amazonaws.com`, el 9,4 %.

  En una red real, esos nombres de CDN serán la principal fuente de falsos positivos. Es una limitación de un
  detector que solo mira la forma del nombre.
- **El ejemplo del README da los mismos veredictos que en 2021**, y `google.com`, `facebook.com` y
  `wikipedia.org` dan «No DGA domain». De los 188 dominios de `tests/data/referencia_netlab.csv` detecta 172
  (91,5 %); están en `dga.dom`, así que es una comprobación de cordura, no una métrica.
- Siguen valiendo las advertencias de la fase 4: no hay dominios DGA reales posteriores a 2021, y la exclusión
  es estricta por SLD.

**Tiempos** (Apple Silicon nativo, 12 núcleos): `--ngram`, 19 s; `--main`, 5 min 40 s (2.904.183 dominios);
`--secondary`, 3 min 54 s; `--umbrella`, 23 s; `--train full`, 33 s; `--train tiny`, 9 s; cada evaluación,
entre 2 y 5 s. Bajo Rosetta, en la fase 4, `--secondary` tardó 34 min.

### Modelo de 2021, medido en 2026

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

---

## Implementado, no verificado

Estas funciones tienen código completo y se invocan desde la línea de órdenes, pero **no se han ejecutado**.
No se cuentan como entregadas hasta verificarlas.

| Función | Orden | Estado |
|---|---|---|
| Entrenar las variantes `ngram`, `nongram`, `nosyll` y `nongramnosyll` | `detectdga.py --train …` | Solo se han entrenado y medido `full` y `tiny` |
| Estadística de alfabeto y patrón | `statsdga.py`, opción 3 | Los patrones de las fichas pudieron salir de aquí (suposición) |

**Verificado desde la primera medición:** `--ngram`, `--main`, `--secondary`, `--umbrella`, `--train full`,
`--train tiny`, `--test_secondary` y `--test_umbrella`, con los datos del juego 2026 (fase 5; tiempos en
«Métricas del detector»).

---

## A medias

| Qué | Estado | Cuánto falta | Dónde |
|---|---|---|---|
| **Estadística de n-gramas** (`statsdga.py`, opción 9) | En la rama de dominios reales mide `1,google` en lugar de `google` (no separa el rango del CSV) | Separar el campo | `statsdga.py`, `calcngram()` |
| **Modo de reparto del corpus** | Solo funciona el modo por defecto; `dga.create(configs=1)` falla con `UnboundLocalError` (verificado en la fase 3) | Definir la variable en todas las ramas | `dga.py`, `create()` |

**Resuelto desde la primera medición:** el conjunto secundario (`--secondary` comprobaba un fichero y leía
otro, C6), la evaluación con él y la comprobación del diccionario (miraba cuatro veces `tranco.ng1`, C9).
La evaluación con Alexa, contaminada con el entrenamiento, se sustituyó por Umbrella (C3, C5).

---

## Fuera de lo entregado

**Abandonado**

- **Comprobar por DNS si un dominio existe.** El código está (`existdomain()` y `checkdomains()` en
  `detectdga.py`), pero nadie lo llama. `dnspython` ya no es una dependencia: solo se importa dentro de esa
  función.
- **Modelo «tiny» en el detector.** Se entrena y se publica, pero `--check` siempre usa `full`.

**Declarado y no implementado**

- **Reglas YARA.** Hay 35 reglas en `yara/` y el README dice que se extrajeron de Malpedia. El programa solo
  imprime su nombre de fichero (`dga.py:62-63`) y nunca las aplica a nada.

**Lo que la documentación prometía y el código no cumplía**

| Promesa (README de 2021) | Hoy |
|---|---|
| «Python 3.7 o superior» con `pip install -r requirements.txt` | **Resuelto:** Python 3.12 o 3.13, con `requirements.txt` o `requirements-lock.txt` |
| Crear el conjunto secundario con `--secondary` | **Resuelto** (C6) |
| `lookdga.py -C > ml-data/mydgas.dom` produce el CSV de prueba | **Resuelto** (C13) |
| Se puede validar con Alexa | **Resuelto:** Umbrella, sin dominios del entrenamiento (C3, C5) |
| `statsdga.py` usa el «Alexa top million» | **Resuelto:** usa Tranco; el README lo explica |
| El ejemplo `-b --check` atribuye los dominios DGA | **Sigue igual:** atribuye 1 de 3; el README lo explica |
| La sospecha por patrón «detecta» DGA | **Sigue igual:** `google.com` sale como sospechoso de 6 familias; el README lo explica |

**Fuera por diseño** (ver «No objetivos» en `docs/IDEA.md`): no hay servicio, interfaz gráfica ni lectura de
registros de DNS o proxy, no se contacta con los dominios y no se hace reversing nuevo.

**Decidido para el futuro y no presente hoy:** entrada por fichero, exportación de resultados, datos DGA
recientes y el flujo de muestra a dominios. Están en `docs/FUTURE.md`.

---

## Definición de terminado

**La de 2021**, deducida de lo que el repositorio mantenía:
- **Calidad:** «funciona en la máquina del autor con los datos del autor». Las versiones estaban fijadas, pero
  no la plataforma ni la versión de Python.
- **Pruebas:** ninguna, ni CI ni resultados de evaluación guardados.
- **Documentación:** un README con ejemplos de uso y las fuentes de datos.
- **Datos:** los resultados intermedios necesarios para usar el detector, versionados en git.

Era la definición de un trabajo académico entregado, no la de un producto mantenido.

**La de hoy**, la de la etapa 1.1 de `docs/FUTURE.md` tal como se ha aplicado:
- **Calidad:** se instala con `requirements-lock.txt` en Python 3.12 y 3.13; los datos se descargan y se
  verifican con `fetchdata.py`; ningún script descarga nada al ejecutarse.
- **Pruebas:** `pytest` con pruebas de caracterización, de cada corrección y de los datos instalados frente al
  manifiesto. La CI (`.github/workflows/tests.yml`) las ejecuta en Linux, macOS y Windows con 3.12 y 3.13;
  hasta la publicación solo se ha comprobado en local (Linux con `act` y macOS), y Windows está sin verificar.
- **Documentación:** README, este documento y `docs/`, con métricas, limitaciones y decisiones. Toda
  afirmación sobre el comportamiento está verificada o marcada como no verificada.
- **Datos:** fuera de git, como assets de release o descargados de su origen, con tamaño, SHA‑256, fuente y
  licencia en `ml-data/MANIFEST`. Los modelos llevan metadatos que los atan a su diccionario y a su lista de
  sufijos.
