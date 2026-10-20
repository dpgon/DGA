# DGA: diseño de correcciones (actualización de versiones y datos)

> Diseño acordado con el autor el 2026-10-18. Se apoya en `docs/ESTUDIO.md`, `docs/MVP.md` y
> `docs/ARCHITECTURE.md`. Las comprobaciones de fuentes externas citadas se hicieron ese mismo día.
>
> **Estado: implementado** el 2026-10-19, en las fases 0–5 de `TODO.md` (commit `96e4046`), y publicado el
> 2026-10-20 (etiqueta `v2026`, releases `data-2026` y `model-2026`). Las desviaciones respecto a este diseño están en «Implementación y desviaciones», al
> final del documento. Las referencias de línea de cada corrección son las del código de 2021.

## Qué se va a corregir

El objetivo es poner al día el proyecto en **versiones y datos**:

- que se instale con un Python vigente y con las versiones actuales de sus librerías;
- que el detector se reentrene con datos actuales y reproducibles, y se guarde en un formato que no ejecute
  código al cargarse;
- que sus evaluaciones sean independientes del entrenamiento;
- que los datos pesados salgan de git y se publiquen como assets de release verificables.

Entran también los cuatro errores que están en ese camino y que, sin arreglar, impedirían verificar el
resultado:

- `--secondary` roto;
- desalineación de veredictos en `--check`;
- CSV sucio de `-C`;
- descarga de NLTK al importar.

**Queda fuera** todo lo que no es versiones ni datos, salvo esos cuatro:

- los falsos positivos de los patrones;
- la ventana de la fuerza bruta;
- la entrada por fichero;
- YARA;
- la fidelidad de los generadores.

Ver «Lo que no se arregla ahora».

## Resumen

| ID | Título | Tipo | Severidad | Causa |
|---|---|---|---|---|
| C1 | Dependencias no instalables en plataformas actuales | Error | Crítica | Confirmada (síntoma reproducido); el mecanismo de `pkg_resources`, hipótesis |
| C2 | El modelo no carga en scikit-learn actual; persistencia en pickle | Diseño | Crítica | Confirmada |
| C3 | Datos legítimos de 2021 y Alexa retirado | Limitación | Alta | Confirmada |
| C4 | Fuente de dominios DGA caída y sin datos recientes | Limitación externa | Alta | Síntoma confirmado; cierre del feed, hipótesis |
| C5 | Conjuntos de evaluación contaminados con el entrenamiento | Error | Alta | Confirmada |
| C6 | `--secondary` siempre falla | Error | Alta (bloquea C5) | Confirmada |
| C7 | Lista de sufijos públicos de 2021 | Limitación | Media | Diferencia medida; efecto en el modelo, hipótesis |
| C8 | Datos y modelos en git, al límite de GitHub | Diseño | Alta | Confirmada |
| C9 | `checktranco()` solo comprueba `ng1` | Error | Baja | Confirmada |
| C10 | `n_jobs=14` fijo | Diseño | Baja | Confirmada |
| C11 | Descarga de NLTK al importar | Diseño | Media | Confirmada |
| C12 | `--check` desalinea veredictos y se cae con la lista vacía | Error | Alta | Confirmada |
| C13 | `-C` mezcla líneas de estado ANSI con el CSV | Error | Media | Confirmada |

## Orden de implementación

| Fase | Correcciones | Por qué en este orden |
|---|---|---|
| F0 | Etiqueta `v2021` y su release | Congela lo reproducible antes de tocar nada (D7) |
| F1 | C1 + C11 | Sin entorno actual no hay nada que ejecutar; NLTK es parte de la instalación |
| F2 | C12 + C13 | Hacen fiables la salida del detector y del corpus antes de usarlas para verificar |
| F3 | C8 + C7 + C3 + C4 | Primero se fija dónde viven los datos y después se obtienen |
| F4 | C6 + C9 + C5 | Tocan el mismo código de construcción de conjuntos (`detectdga.py:217-517,729-815`) |
| F5 | C2 + C10 | El reentrenamiento depende de todo lo anterior; C10 toca la misma línea |

---

## C1. Dependencias no instalables en plataformas actuales

- **Síntoma:** `pip install -r requirements.txt` falla en Python 3.9.6 nativo arm64. Las versiones exactas no
  existen para Python ≥ 3.10.
- **Reproducción:**
  ```bash
  python3.9 -m venv v
  v/bin/pip install -r requirements.txt
  ```
  Falla con `Failed to build 'pandas' … No module named 'pkg_resources'`. Con `pip download --only-binary :all:`,
  `scikit-learn==0.24.2`, `scipy==1.7.1` y `pandas==1.3.1` dan «No matching distribution» en arm64 (verificado,
  `docs/MVP.md` §0).
- **Causa:**
  - `requirements.txt` es un `pip freeze` del entorno del autor de 2021 (commit `269b362`). Fija 14 versiones
    exactas, transitivas incluidas, publicadas para Python ≤ 3.9 y sin binarios para arm64.
  - Python 3.9 dejó de tener soporte en octubre de 2025.
  - **Hipótesis** sobre el fallo de compilación: el `setup.py` de pandas 1.3.1 importa `pkg_resources`, y el
    entorno de compilación aislado de pip instala un setuptools actual que ya no lo ofrece.
  - El README promete «python3.7 or above», y eso es falso.
- **Arreglo acordado (D1):**
  - `requirements.txt` declara **requisitos mínimos de verdad**, solo directos: scikit-learn, pandas, numpy y
    nltk, con la cota inferior que se valide (orientativo: scikit-learn ≥ 1.9, pandas ≥ 3.0, numpy ≥ 2, nltk
    ≥ 3.9). `dnspython` sale, porque solo lo usa código muerto (`detectdga.py:10,69-106`).
  - Nuevo `requirements-lock.txt`, generado con `uv pip compile requirements.txt`, con versiones exactas para
    reproducir. Se instala con `pip install -r requirements-lock.txt`, sin necesitar uv.
  - Pythons soportados: **3.12 y 3.13**.
- **Por qué este y no los otros:**
  - Subir los números del freeze (parche mínimo) repetiría el problema en dos años.
  - Empaquetar con `pyproject.toml` (rediseño) es más de lo que pide «poner al día».
- **Archivos:** `requirements.txt`, `requirements-lock.txt` (nuevo), `README.md` (instalación).
- **Regresiones posibles:**
  - cambios de API en pandas 3.0 (copy-on-write, `inplace=True` en `df.drop`, `detectdga.py:524-549`) y en numpy 2;
  - avisos o cambios de comportamiento en `LegalitySyllableTokenizer` de nltk 3.9;
  - los generadores con `ctypes` no deberían verse afectados.
- **Prueba que lo cubre:**
  - CI en GitHub Actions con una matriz de {ubuntu, macos-arm64, windows} × {3.12, 3.13} que instala
    `requirements-lock.txt` y ejecuta `pytest`;
  - una prueba de humo que importa `dga`, `ngram` y `detectdga` sin red.

## C2. Modelo atado a scikit-learn 0.24.2 y persistido en pickle

- **Síntoma:** en Python 3.13.16 con scikit-learn 1.9.1, cargar `ml-data/full.pkl` da `ValueError: node array
  from the pickle has an incompatible dtype` (verificado). Además, cargar cualquier `.pkl` del repositorio
  ejecuta código arbitrario.
- **Reproducción:** `python -c "import pickle; pickle.load(open('ml-data/full.pkl','rb'))"` en ese entorno.
- **Causa:**
  - El pickle serializa la estructura interna de los árboles de scikit-learn 0.24.2 (`_sklearn_version 0.24.2`
    en `ml-data/full.pkl`). En versiones posteriores, el registro de nodo ganó el campo `missing_go_to_left`
    (lo dice el propio mensaje de error), y el formato antiguo ya no es compatible.
  - La persistencia se hace con `pickle.dump`/`pickle.load` (`detectdga.py:564,571,623,629,695,701`) y, para
    los n-gramas, con `DataFrame.to_pickle`/`pd.read_pickle` (`ngram.py:46-55`).
- **Arreglo acordado (D2):**
  - **Reentrenar** con el entorno de C1 y los datos de F3–F4, con las mismas características (24) y los mismos
    hiperparámetros (`n_estimators=30`, `min_samples_leaf=5`, `random_state=1`, `test_size=0.2`,
    `random_state=100`, `detectdga.py:555,567`), para que el resultado se pueda comparar con 2021.
  - Guardar modelo y escalador con **`skops`**, un formato que no ejecuta código al cargarse y que valida los
    tipos admitidos. La versión se fija en `requirements.txt` al implementarlo.
  - **Consecuencia derivada de D2:** el diccionario de n-gramas (`tranco.ng1-4`) deja de ser un pickle de
    pandas y pasa a un formato de texto (CSV o JSON con n-grama → valor). Se regenera igualmente en C3.
  - Junto a cada modelo, un **fichero de metadatos** con:
    - versiones de Python y de las librerías;
    - fecha;
    - ID de la lista Tranco y fuentes DGA, con sus SHA‑256;
    - SHA‑256 del diccionario de n-gramas y de la lista de sufijos;
    - hiperparámetros;
    - métricas por conjunto de evaluación.
  - Al cargar se comprueba que el diccionario coincide con el hash de los metadatos. Si no coincide, el
    programa se detiene con un mensaje claro.
  - El modelo de 2021 no se convierte: se archiva en la release `v2021` (D7).
  - Se reentrenan y publican las variantes `full` y `tiny`. Las demás (`ngram`, `nongram`, `nosyll`,
    `nongramnosyll`) se pueden seguir entrenando con `--train`, pero no se publican.
- **Por qué este:**
  - Seguir con pickle y comprobar la versión no quitaría el riesgo de ejecución de código, que es el principal
    de `docs/ARCHITECTURE.md` §7.
  - No reentrenar dejaría el detector inutilizable fuera del entorno de 2021.
- **Archivos:** `detectdga.py` (`traindata`, `testsecdata`, `testdomains`, `loadngram`/`createstdngram`),
  `ngram.py` (`save`/`load`), `requirements.txt`.
- **Regresiones posibles:**
  - **los veredictos cambian respecto a 2021**: el ejemplo del README puede dar otro resultado;
  - si el modelo nuevo se carga con un diccionario de n-gramas distinto, las predicciones se rompen en
    silencio (por eso el hash);
  - las características se calculan en cinco sitios casi idénticos (`detectdga.py:257-680`), y cualquier
    desfase entre el entrenamiento y la predicción es invisible.
- **Prueba que lo cubre:**
  - `tests/test_model.py`: carga el modelo publicado en un entorno limpio, sin `pickle`;
  - comprueba que la carga falla si se altera el hash del diccionario;
  - comprueba que, sobre un conjunto de referencia fijo (`google.com`, `facebook.com`, `wikipedia.org` y dominios
    generados de las 11 familias con confirmación externa, `docs/MVP.md` §3), los veredictos son los esperados,
    con un umbral de aciertos y no por igualdad exacta;
  - una prueba de **paridad de características**: el vector que calcula `testdomains` para un dominio es idéntico
    al de la fila correspondiente de `main.pkl`.

## C3. Datos legítimos de 2021 y Alexa retirado

- **Síntoma:** los dominios legítimos son de 2021 (`ml-data/tranco-*.dom`, lista Tranco `9Q72`). La prueba
  «Alexa» (`ml-data/alexa.dom`) y las estadísticas (`DGAs/wordlist/top-1m.csv`, 638.215 líneas) dependen de un
  ranking que Alexa retiró en 2022.
- **Causa:** instantánea fija versionada en el primer commit (`fde8bb0`). El README describe cómo construirla,
  pero solo para la lista `9Q72`.
- **Arreglo acordado (D4):**
  - **Tranco actual con ID permanente** para los tres conjuntos, divididos igual que en el README
    (`1–1.500.000` → `main`, `1.500.001–2.000.000` → `test2`, el resto → `ngram`). La última lista diaria
    comprobada es la `8PX8V` (2026-10-17); al implementar se elige una y su ID queda en los metadatos.
  - **Cisco Umbrella top‑1M** (`umbrella-static/top-1m.csv.zip`, disponible y actualizada el 2026-10-18)
    sustituye a Alexa como prueba de una fuente distinta. Como se basa en DNS y trae subdominios, se reduce a
    dominios registrables con la lista de sufijos de C7 y se le quita todo lo que esté en el entrenamiento (C5).
  - `statsdga.py` pasa a usar la nueva lista Tranco en lugar de `top-1m.csv`
    (`statsdga.py:110,145,183,220,260,543`).
- **Por qué este:**
  - Mantener la `9Q72` sería comparable con 2021, pero no estaría «al día».
  - Retirar la prueba de fuente distinta dejaría solo una evaluación con datos de la misma lista que el
    entrenamiento.
- **Archivos:** `detectdga.py` (`createalexadataset` → conjunto Umbrella; opciones `--alexa`/`--test_alexa`),
  `statsdga.py`, `README.md`.
- **Regresiones posibles:**
  - si se renombran `--alexa` y `--test_alexa`, se rompe la compatibilidad de la CLI (decisión de
    implementación: mantener los nombres antiguos como alias);
  - con la nueva lista, las estadísticas de `statsdga.py` cambiarán.
- **Prueba que lo cubre:** el manifiesto de C8 registra el ID de Tranco y los SHA‑256. Una prueba comprueba
  que los tres conjuntos Tranco no comparten ningún dominio y que su tamaño coincide con el manifiesto.

## C4. Fuente de dominios DGA caída y sin datos recientes

- **Síntoma:** `https://data.netlab.360.com/feeds/dga/dga.txt` no responde: la conexión TCP se establece, pero
  no llega respuesta HTTP en 20 s (comprobado el 2026-10-18).
- **Causa:** externa. No se encontró ningún anuncio de cierre, así que que el feed esté discontinuado es una
  **hipótesis**. Las alternativas comprobadas ese día:
  - Bambenek OSINT: HTTP 403;
  - `tamglaeser/dga-feed`: último commit en 2020;
  - DGArchive (FKIE): la web responde, pero el acceso es restringido y hay que solicitarlo;
  - `harpomaxx/dga-detection` (Hugging Face): disponible, CC BY 2.0, última modificación 2023-05-10.
- **Arreglo acordado (D3):**
  - **Entrenamiento:** el `ml-data/dga.dom` de 2021 (360 Netlab, datos reales). Se conserva como asset de
    datos con su SHA‑256.
  - **Evaluación independiente:** `harpomaxx/dga-detection`, quitando los dominios que también estén en
    `dga.dom` (C5).
  - **Datos recientes:** se solicita acceso a DGArchive en paralelo. Si se concede, se usarán para medir el
    envejecimiento y reentrenar en una corrección posterior. Esto no bloquea esta.
    *Actualización 2026-10-19: el autor decide no pedir acceso de momento. Además, los dominios de Hugging
    Face resultaron ser de 2016 o sin fecha, así que la evaluación no tendrá datos DGA reales posteriores a
    2021. Las métricas deben decirlo.*
  - **Prueba secundaria:** el corpus de los generadores propios (`lookdga.py -C`, C13) con fechas de
    2025–2026. Se usa solo para evaluar, nunca para entrenar, porque sería circular y 39 de los 50 generadores
    no están verificados.
  - **Repositorio de Bader** (último commit 2025-09-28): fuente de casos de referencia para comprobar la
    fidelidad, fuera de esta corrección.
- **Por qué este:**
  - Entrenar con generadores propios haría circular la evaluación.
  - Esperar a DGArchive bloquearía la actualización por un tercero.
- **Archivos:** `detectdga.py` (conjunto secundario con dos orígenes DGA), `README.md` (fuentes).
- **Regresiones posibles:**
  - el modelo seguirá sin conocer familias posteriores a 2021;
  - la evaluación con Hugging Face puede dar cifras peores que las de 2021, y eso no es un fallo sino
    información.
- **Prueba que lo cubre:** el manifiesto registra el SHA‑256 de `dga.dom` y del dataset de Hugging Face. Una
  prueba comprueba que ningún dominio de evaluación está en el entrenamiento (C5).
- **Limitación que hay que documentar:** el README y los metadatos del modelo dirán explícitamente que no hay
  datos DGA reales posteriores a 2023.

## C5. Conjuntos de evaluación contaminados

- **Síntoma:** 310.412 de los 500.000 dominios de `alexa.dom` están también en `tranco-main.dom`, y 31.763 de
  los 444.228 dominios únicos de `mydgas.dom` están en `dga.dom`. Medido con `sort -u` y `comm -12`
  (`docs/ESTUDIO.md` §6).
- **Causa:**
  - `createtestdataset()` (`detectdga.py:350-457`) y `createalexadataset()` (`:460-517`) leen sus ficheros tal
    cual, sin excluir lo que haya en los conjuntos de entrenamiento.
  - Alexa y Tranco son rankings de los mismos dominios populares.
  - Los generadores propios y el feed de Netlab coinciden en las familias que no dependen de la fecha
    (`docs/MVP.md` §3).
- **Arreglo acordado:**
  - al construir cada conjunto de evaluación, se excluye todo dominio y todo SLD presente en el conjunto de
    entrenamiento (`main`, tanto la parte legítima como la DGA) y en el de n-gramas;
  - se informa de cuántos se quitaron;
  - se guarda el recuento en los metadatos.
  - La comparación se hace en minúsculas y sobre el dominio registrable (C7).
- **Archivos:** `detectdga.py` (`createtestdataset`, `createalexadataset`/Umbrella).
- **Regresiones posibles:**
  - los conjuntos de evaluación se reducen bastante (en Alexa, del 62 % al 0 % de solape);
  - cargar `main` en memoria para excluir aumenta el consumo de memoria.
- **Prueba que lo cubre:** `tests/test_datasets.py` construye conjuntos a partir de ficheros pequeños con
  solapes conocidos y comprueba que la intersección es cero y el recuento correcto. También comprueba los
  conjuntos reales contra el manifiesto, en una prueba marcada como lenta.

## C6. `--secondary` siempre falla

- **Síntoma:** `python detectdga.py --secondary` → «Files ml-data/tranco-secondary.dom and/or
  ml-data/mydgas.dom not found» (verificado).
- **Causa:** `main()` comprueba `ml-data/tranco-secondary.dom` (`detectdga.py:775`), pero
  `createtestdataset()` lee `ml-data/tranco-test2.dom` (`:356`), que es el nombre que usan el README y el
  repositorio.
- **Arreglo acordado:** usar `tranco-test2.dom` en los dos sitios, definido una sola vez como constante
  compartida para que no puedan divergir.
- **Por qué:** es el nombre documentado y el que existe; cambiar el de la lectura rompería el README.
- **Archivos:** `detectdga.py:356,775-778`.
- **Regresiones posibles:** ninguna conocida.
- **Prueba que lo cubre:** `tests/test_cli.py` ejecuta `--secondary` en un directorio temporal con ficheros
  mínimos y comprueba que crea `secondary` sin el mensaje de error.

## C7. Lista de sufijos públicos de 2021

- **Síntoma:** `DGAs/wordlist/effective_tld_names.dat` tiene 9.174 entradas. La versión actual de
  publicsuffix.org tiene 10.398: hay 2.270 nuevas y 1.046 que ya no están (medido el 2026-10-18).
- **Causa:**
  - fichero fijo del primer commit;
  - `sldtld()` descarta en silencio todo dominio cuyo sufijo no esté en la lista (`detectdga.py:125`);
  - **hipótesis:** con datos de 2026 se perderían dominios legítimos con sufijos nuevos, y el entrenamiento
    quedaría sesgado.
- **Arreglo acordado (D4):**
  - sustituir el fichero por la versión actual, con su fecha y su SHA‑256 en el manifiesto y en los metadatos
    del modelo;
  - incluir la sección privada (p. ej. `ddns.net`), como ahora;
  - los 154 sufijos añadidos a mano «desde Alexa» (`detectdga.py:31-58`) se conservan y se documentan como
    tales.
- **Archivos:** `DGAs/wordlist/effective_tld_names.dat`, `detectdga.py:28-66`.
- **Regresiones posibles:**
  - cambia qué dominios se aceptan, y con ello las características: no es compatible con el modelo de 2021
    (se reentrena en C2);
  - `crctld` cambia de valor para dominios cuyo sufijo efectivo pasa a ser otro.
- **Prueba que lo cubre:** el SHA‑256 de la lista que tiene el modelo se compara al cargar (C2). Una prueba
  unitaria de `sldtld()` cubre sufijos de varios niveles, privados y nuevos.

## C8. Datos y modelos en git, al límite de GitHub

- **Síntoma:**
  - 367 MB versionados en `ml-data/`;
  - `full.pkl` pesa 99.897.641 bytes, a unos 100 KB del límite de 100 MB por fichero de GitHub;
  - los datos nuevos (Tranco completa, Umbrella, Hugging Face) y los modelos nuevos lo superarían.
- **Causa:** decisión de 2021 de versionarlo todo para que `--check` funcionara al clonar (README: «The
  repository has the full model»).
- **Arreglo acordado (D5, D7):**
  - Los datos y modelos se publican como **assets de releases de GitHub** (hasta 2 GB por fichero).
  - En git queda un **manifiesto** (`ml-data/MANIFEST`: nombre, URL, tamaño, SHA‑256) y un **paso de descarga
    y verificación** documentado, que se ejecuta una vez al instalar y no se repite.
  - `ml-data/` se ignora en git, salvo el manifiesto.
  - Lo de 2021 se retira del árbol de trabajo después de etiquetar `v2021` (F0). Sigue completo en la etiqueta,
    en su release y en la historia, que **no se reescribe**.
  - `DGAs/wordlist/top-1m.csv` sale también, porque su función pasa a la nueva Tranco (C3). Los diccionarios
    de los generadores y la lista de sufijos se quedan en git, porque son pequeños y los necesita
    `lookdga.py`.
- **Por qué este:**
  - En GitHub gratuito, la cuota de ancho de banda de Git LFS (1 GB/mes) la agotaría cualquier clon del
    repositorio público.
  - Recortar el modelo para que quepa condiciona el modelo al alojamiento.
- **Archivos:** `.gitignore`, `ml-data/MANIFEST` (nuevo), `README.md` (instalación), `detectdga.py`
  (mensajes cuando faltan ficheros).
- **Regresiones posibles:**
  - **clonar ya no basta**: sin el paso de descarga, `--check` no funciona y tiene que fallar con un mensaje
    que diga qué hacer;
  - el clon no se aligera, porque la historia conserva los 367 MB;
  - si las releases dejan de existir, los datos se pierden: hay que documentar que el manifiesto con los
    hashes permite comprobar cualquier copia.
- **Prueba que lo cubre:** una prueba que, con `ml-data/` vacío, ejecuta `--check` y comprueba el mensaje y el
  código de salida distinto de 0. Otra que verifica cada fichero descargado contra el manifiesto.

## C9. `checktranco()` solo comprueba `ng1`

- **Síntoma:** si falta `tranco.ng2`, `ng3` o `ng4`, la comprobación pasa y el fallo aparece después, dentro
  de `loadngram`, que además se lo traga (`detectdga.py:213`).
- **Causa:** `detectdga.py:730-731` repite cuatro veces `isfile('ml-data/tranco.ng1')`.
- **Arreglo acordado:** comprobar los cuatro ficheros, o los que defina el nuevo formato de C2, y que
  `loadngram` informe del error en lugar de devolver `None` en silencio.
- **Archivos:** `detectdga.py:203-214,729-734`.
- **Regresiones posibles:** ninguna.
- **Prueba que lo cubre:** `tests/test_cli.py`, que quita cada fichero por turno y espera el mensaje
  correspondiente.

## C10. `n_jobs=14` fijo

- **Síntoma:** el entrenamiento y la predicción lanzan 14 hilos sea cual sea la máquina (en `--check` se ve
  «Using backend ThreadingBackend with 14 concurrent workers»).
- **Causa:** `detectdga.py:567`, ajustado a la máquina Linux del autor (dicho por el autor). El valor viaja
  dentro del modelo guardado.
- **Arreglo acordado:** `n_jobs=-1` (todos los núcleos disponibles) al entrenar, y fijar `model.n_jobs` al
  cargar en lugar de heredarlo del fichero.
- **Archivos:** `detectdga.py:567`, carga del modelo en `testsecdata`/`testdomains`.
- **Regresiones posibles:** en máquinas con muchos núcleos, la predicción de pocos dominios puede tardar más
  por el coste de arrancar los hilos (no medido).
- **Prueba que lo cubre:** la prueba de C2 comprueba que el modelo cargado tiene `n_jobs` igual a lo
  configurado.

## C11. Descarga de NLTK al importar

- **Síntoma:** importar `detectdga.py` o `statsdga.py` sin el corpus `brown` lanza `nltk.download('brown')`
  sin avisar. Sin red, falla de forma poco clara. Incumple «sin conexión una vez instalado» (`docs/IDEA.md`).
- **Causa:** `detectdga.py:20-23` y `statsdga.py:10-13` comprueban el corpus y lo descargan a nivel de
  módulo.
- **Arreglo acordado:**
  - La descarga del corpus pasa al **paso de instalación** de C8, con destino documentado (`NLTK_DATA`).
  - Al importar no se descarga nada.
  - Si falta el corpus cuando se necesita, el programa termina con un mensaje que indica el paso de
    instalación.
- **Archivos:** `detectdga.py:20-23`, `statsdga.py:10-13`, `README.md`.
- **Regresiones posibles:** quien ya tuviera el corpus no nota nada. Quien no lo tenga ve un error donde antes
  había una descarga.
- **Prueba que lo cubre:** `tests/test_offline.py` sustituye `nltk.download` por una función que falla y
  comprueba que importar los módulos no la llama y que el mensaje de error es el esperado.

## C12. `--check` desalinea veredictos y se cae con la lista vacía

- **Síntoma:**
  - `python detectdga.py --check bbc.com google.com ughdnmmgdpscliraqnpl.com` imprime «No DGA» para `bbc.com`
    (es el veredicto de google), **«DGA generated» para `google.com`** (es el del tercero), y el tercero
    desaparece;
  - `--check bbc.com` → `ValueError: Found array with 0 sample(s)` (los dos verificados, `docs/MVP.md` §8).
- **Causa:**
  - `testdomains()` solo añade a `domains` los dominios que pasan `sldtld()` (`detectdga.py:650-651`), pero al
    imprimir usa el índice de la predicción sobre la lista original: `domlist[c]` (`:709-710`, también `:713,718`);
  - si no pasa ninguno, `sc.transform` recibe una matriz vacía (`:698`);
  - los descartes no se comunican (`sldtld`, `:113-128`).
- **Arreglo acordado:**
  - guardar junto a cada vector el dominio del que sale e imprimir los veredictos emparejados con ellos;
  - listar los dominios descartados con su motivo (SLD de 3 caracteres o menos, sufijo desconocido);
  - no llamar al modelo si no queda ninguno;
  - normalizar la entrada a minúsculas antes de evaluar.
  - El tratamiento de `www.` y de los subdominios **no cambia** en esta corrección: solo se informa de ellos.
- **Por qué no más:** rediseñar el tratamiento de subdominios cambia qué evalúa el modelo y pertenece a una
  corrección de funcionalidad, no de versiones.
- **Archivos:** `detectdga.py:642-726`.
- **Regresiones posibles:** la salida de `--check` cambia de forma (líneas nuevas de descartados), lo que
  afecta a quien la procese con scripts.
- **Prueba que lo cubre:** `tests/test_check.py` con un modelo de prueba que devuelve un veredicto distinto
  para cada dominio:
  - la entrada `[bbc.com, google.com, X]` empareja cada veredicto con su dominio;
  - `[bbc.com]` termina sin excepción e informa del descarte;
  - `GOOGLE.COM` se evalúa como `google.com`.

## C13. `-C` mezcla líneas de estado con el CSV

- **Síntoma:** `python lookdga.py -m banjori -n 2 -C` imprime antes y después de los datos
  `\x1b[96m* Generating domains for: banjori\x1b[0m` y `\x1b[96m* Generated 2 domains\x1b[0m` (verificado).
  Al redirigir la salida, como manda el README, quedan dentro del CSV.
- **Causa:** `dga.create()` imprime el estado por la salida estándar cuando `main=True` (`dga.py:238,283`), la
  misma que los datos (`:271`). `createtestdataset` lo compensa saltando las líneas con `*`
  (`detectdga.py:410`).
- **Arreglo acordado:**
  - las líneas de estado de `create()` van a la **salida de error**, y la salida estándar solo lleva el CSV;
  - el filtro de `*` en `createtestdataset` se conserva, para poder leer los ficheros antiguos.
- **Archivos:** `dga.py:238,283`.
- **Regresiones posibles:** quien ejecute `-C` en la terminal sigue viendo los mensajes (la salida de error se
  muestra); solo cambia lo que se redirige.
- **Prueba que lo cubre:** `tests/test_lookdga.py` ejecuta `lookdga.py -m banjori -n 2 -C` y comprueba que
  todas las líneas de la salida estándar cumplen `^[^,]+,[^,]+,[^,]*,\d{4}-\d{2}-\d{2}$`.

---

## Lo que no se arregla ahora

| Qué | Motivo | Dónde queda |
|---|---|---|
| Falsos positivos de los patrones (`google.com` frente a 6 familias, `dga.py:117-125`) | No es versiones ni datos | `docs/FUTURE.md` 1.1.4 |
| Ventana de la fuerza bruta (10 posiciones, 366 días) y fecha engañosa en familias sin fecha | No es versiones ni datos | `docs/FUTURE.md` 1.1.5 |
| Tratamiento de `www.` y subdominios en `--check` | Cambia qué evalúa el modelo (ver C12) | `docs/FUTURE.md` 1.1.3 |
| Fidelidad de los 39 generadores sin confirmación externa | Necesita casos de referencia del repositorio de Bader; trabajo propio | `docs/FUTURE.md` 1.1.8 |
| Duplicación del extractor de características en cinco sitios | Rediseño; aquí se mitiga con la prueba de paridad de C2 | `docs/ARCHITECTURE.md` §12, punto 6 |
| `eval` en `dga.py`/`ngram.py` y `except:` desnudos en general | No es versiones ni datos. El `eval` de `ngram.py` desaparece de forma natural si C2 cambia el formato del diccionario, pero no es un objetivo | `docs/ARCHITECTURE.md` §12 |
| Datos DGA reales posteriores a 2023 | Dependen del acceso a DGArchive | Corrección posterior; `docs/FUTURE.md` 1.2.1 |
| Familias nuevas en el catálogo | Fuera del alcance «versiones y datos» | `docs/FUTURE.md` 1.2.4 |
| Reglas YARA de 2021 | Pertenecen a la etapa 1.3 | `docs/FUTURE.md` 1.3.3 |
| `.idea/` versionado | No es versiones ni datos; decisión del autor | `docs/ARCHITECTURE.md` §12, punto 17 |
| Empaquetado (`pyproject.toml`, puntos de entrada) | Descartado en D1 | Ideas aparcadas |

## Decisiones tomadas

| # | Decisión | Opciones que había | Motivo de la elegida |
|---|---|---|---|
| D1 | Requisitos mínimos reales + `requirements-lock.txt` (uv pip compile), Python 3.12/3.13 | Subir el freeze · mínimos + bloqueo · `pyproject.toml` + `uv.lock` | Ataca la causa (el freeze) sin rediseñar el proyecto; reproducible y no ata a una plataforma |
| D2 | Reentrenar y guardar con `skops` + metadatos; n-gramas en formato de texto | `skops` · pickle con comprobación de versión · no reentrenar | Elimina la dependencia de la estructura interna **y** la ejecución de código al cargar |
| D3 | Entrenar con `dga.dom` 2021, evaluar con Hugging Face sin solapes, pedir DGArchive en paralelo, generadores propios solo como prueba | Lo elegido · esperar a DGArchive · renunciar a datos recientes | Reproducible ya con datos abiertos y reales; no hay circularidad; DGArchive se suma sin bloquear |
| D4 | Tranco actual con ID fijo para los tres conjuntos, Umbrella en lugar de Alexa, PSL actual, `statsdga` con Tranco | Lo elegido · solo Tranco · mantener `9Q72` y limpiar Alexa | Datos de hoy, reproducibles por ID, con una prueba de fuente distinta de verdad |
| D5 | Datos y modelos como assets de release con SHA‑256 y un paso de descarga | Release assets · Git LFS · seguir en git recortando el modelo | Sin límite de tamaño ni cuotas, verificable, y cumple «sin conexión una vez instalado» |
| D6 | Incluir C11, C12 y C13 | Las tres · solo NLTK · ninguna | Sin C12 las comprobaciones del modelo nuevo pueden mentir; C13 limpia el corpus; C11 es parte de la instalación |
| D7 | Etiquetar `v2021` y retirar los ficheros de 2021 del árbol de trabajo | Etiquetar y retirar · mover a `ml-data/2021/` · directorio `data/` aparte | Un solo diseño de rutas; lo de 2021 sigue completo en la etiqueta y su release |

## Riesgos del conjunto

- **`detectdga.py` es lo más tocado:** C2, C5, C6, C9, C10, C11 y C12 caen en el mismo fichero, que no tiene
  pruebas y repite el extractor de características cinco veces. Las pruebas de `tests/` de cada corrección
  deben existir **antes** de cambiar el código, para que la primera ejecución las vea fallar.
- **Los veredictos del detector cambiarán** por el modelo, los datos y la lista de sufijos nuevos. Hay que
  comprobar a mano:
  - el ejemplo del README (`--check` con los cinco dominios) y anotar los resultados nuevos en el README;
  - que `google.com`, `facebook.com` y `wikipedia.org` siguen saliendo «No DGA»;
  - que las métricas sobre Hugging Face y Umbrella son razonables antes de publicarlas.
- **Compatibilidad con pandas 3.0 y numpy 2:** antes de reentrenar, ejecutar una vez `--ngram`, `--main`,
  `--train` y `--test_*` sobre un subconjunto pequeño en el entorno nuevo, para que los fallos de API salgan
  en minutos y no tras horas.
- **Tiempo de reentrenamiento:** no medido; **suposición**: horas. Conviene medirlo con el subconjunto y
  extrapolar.
- **Quien clona** necesita un paso más (C8). El README tiene que decirlo en la primera sección de
  instalación.
- **Dependencia de terceros:** las releases de GitHub, Tranco, Umbrella y Hugging Face. El manifiesto con los
  hashes es lo que permite comprobar cualquier copia si una fuente desaparece.
- **Licencias de los datos:** comprobar antes de publicar los assets:
  - la licencia de la lista Tranco;
  - los términos de Cisco Umbrella;
  - la CC BY 2.0 del dataset de Hugging Face (exige atribución);
  - la del feed de 360 Netlab, que se redistribuye.

## Documentación que hay que actualizar al implementarlo

| Documento | Qué cambia |
|---|---|
| `README.md` | Instalación (Python 3.12/3.13, lock, paso de descarga de datos y del corpus NLTK); quitar las notas «Known issue» resueltas (instalación, `--secondary`, Alexa, desalineación, CSV de `-C`); fuentes de datos nuevas y créditos (Tranco con su ID, Umbrella, Hugging Face); resultados nuevos del ejemplo `--check`; métricas publicadas |
| `docs/MVP.md` | §0 (instalación) y §8–9 (detector) con los criterios verificados de nuevo; sacar C6/C9 de «A medias»; nueva definición de terminado (pruebas y CI existentes) |
| `docs/ARCHITECTURE.md` | Stack (versiones nuevas, `skops`, sin `dnspython`); modelo de datos (formatos, manifiesto, releases); §5.3 Red (sin descarga al importar; descarga en la instalación); §8 Pruebas (comandos `pytest`); §9 Distribución; §11 nuevas decisiones D1–D7; §12 marcar la deuda resuelta |
| `docs/FUTURE.md` | Marcar como hechas las partes de 1.1.1, 1.1.2, 1.1.3 (alineación), 1.1.6, 1.1.7 y 1.1.9 (CSV de `-C`) que cubre esta corrección; dejar en 1.2.1 la dependencia de DGArchive |
| `CLAUDE.md` | Entorno y comandos (sin Rosetta, con la descarga de datos); reglas 6, 7 y 13 (el formato `skops`, las releases en lugar de los ficheros versionados); comando de pruebas |
| `docs/ESTUDIO.md` | No se toca: es la foto de 2021. Si acaso, una nota al principio que remita a este documento |

---

## Implementación y desviaciones

Las trece correcciones están implementadas, con sus pruebas escritas antes que el código. Dónde quedó cada una:

| Fase de `TODO.md` | Correcciones | Pruebas |
|---|---|---|
| 2 | C6, C9, C11, C12, C13 | `tests/test_cli.py`, `tests/test_offline.py`, `tests/test_check.py`, `tests/test_lookdga.py` |
| 3 | C3, C4, C7 (preparación), C8 | `tests/test_fetchdata.py`, `tests/test_data.py`, `tests/test_sldtld.py`, `tests/test_statsdga.py` |
| 4 | C5, C3 (Umbrella) | `tests/test_datasets.py` |
| 5 | C1, C2, C7 (activación), C10 | `tests/test_model.py`, `tests/test_ngram.py`, `tests/test_check.py`; toda la batería en Python 3.12 y 3.13 |

La fase 0 creó la etiqueta `v2021` y su release (D7), y la fase 1, las pruebas de caracterización.

**Desviaciones respecto al diseño:**

- **D3, sin DGArchive.** El autor decidió no pedir acceso (2026-10-19), y los dominios de Hugging Face son de
  2016 o no tienen fecha: no hay datos DGA reales posteriores a 2021. Las métricas lo dicen.
- **C2, alcance mayor que el previsto:**
  - el extractor de características quedó en una sola función, `domainfeatures()`, y no solo mitigado con la
    prueba de paridad (estaba en «Lo que no se arregla ahora»);
  - el `eval` de `ngram.py` desapareció al pasar el diccionario a CSV, como se esperaba;
  - además del diccionario y de la lista de sufijos, la carga comprueba los SHA‑256 del modelo y del escalador;
  - `--main` deja un `ml-data/main.json` con lo que entró en el conjunto, y `--test_*` añade sus métricas a los
    metadatos del modelo;
  - las columnas del CSV de n-gramas son `ngram,value`, en inglés como el código;
  - el conjunto de referencia de la prueba son los 188 dominios de `tests/data/referencia_netlab.csv` (11
    familias), que están en el entrenamiento: sirve de comprobación de cordura, no de métrica.
- **C2, `TRUSTED`.** skops acepta por defecto los estimadores de scikit-learn; la lista explícita solo tiene
  `sklearn.tree._tree.Tree`, que skops no acepta sin más porque un fichero alterado podría leer fuera de
  memoria al predecir.
- **C3, lista Umbrella histórica.** Se usa la del 2026-10-17, porque las listas diarias de Umbrella se publican
  como históricas con unos dos días de retraso y la URL estable de la del día no sirve para reconstruirla.
- **C5, conjunto Umbrella pequeño.** Con el entrenamiento de 2026 (casi toda la lista Tranco `467YX`), la
  exclusión deja 29.681 dominios de Umbrella de 275.443, sobre todo nombres de infraestructura. Por eso su tasa
  de falsos positivos sube al 36,8 %, aunque el modelo no empeora (`docs/MVP.md`, «Métricas del detector»).
- **C7, dónde queda la lista de 2021.** `DGAs/wordlist/effective_tld_names.dat` pasa a ser la lista de 2026, y
  la de 2021 entra en el manifiesto como `ml-data/effective_tld_names-2021.dat` (juego 2021), descargada de
  la etiqueta `v2021`.
- **C8, juegos y nombres.**
  - El manifiesto tiene dos juegos, `2021` y `2026`; el `2026` es el de por defecto desde la fase 5.
  - Los ficheros de 2026 cuyo nombre coincide con uno de 2021 van en `ml-data/2026/`.
  - Las releases nuevas se llaman `data-2026` y `model-2026`, en inglés; solo `data-2026` lleva datos de
    terceros, y solo los que tienen licencia clara. Tranco y Umbrella se descargan de su origen.
  - `detectdga.py --ngram`, `--main`, `--secondary` y `--umbrella` aceptan `--set`.
- **CI.** Antes de publicar se comprobó en local: Linux con `act --bind` (las releases nuevas aún no estaban
  publicadas) y macOS Apple Silicon. En GitHub, Windows falló al principio: git convertía
  `DGAs/wordlist/effective_tld_names.dat` a CRLF y su SHA‑256 dejaba de coincidir. Se corrigió con un
  `.gitattributes` que saca los ficheros de datos byte a byte, y los seis trabajos pasan (2026-10-20). La CI ya
  no se ejecuta al subir etiquetas, para poder publicar las releases antes que el commit que las usa.

## Anexo: resultados del sondeo de compatibilidad (2026-10-18)

Tarea 1.6 de `TODO.md`. Sondeo hecho en una copia del repositorio fuera del árbol y en un entorno aislado.
**No cambia ninguna decisión de este documento**; solo precisa lo que hará falta en la fase 5.

**Entorno:**
- Python 3.13.16, macOS arm64 **nativo**, sin Rosetta;
- scikit-learn 1.9.1, pandas 3.0.6, numpy 2.5.4, nltk 3.10.3, pytest 9.1.1;
- dnspython 2.9.0, que solo se instaló para poder importar `detectdga.py`.

### Pruebas de la fase 1

`pytest -m "not model"` → **241 pruebas pasan** (1 min 31 s; en el entorno 2021 bajo Rosetta tardan
2 min 24 s). La **instantánea de los 50 generadores** (`tests/data/snapshot_2026-10-18.csv`) y la
referencia de Netlab son **idénticas** con las versiones nuevas. Las estadísticas de `statsdga.py`
funcionan.

### Flujo de entrenamiento

Probado con 10.000 líneas por fichero `.dom` (`dga.dom` muestreado cada 145 líneas):

| Paso | Resultado | Tiempo |
|---|---|---|
| `--ngram` | Funciona | 1,5 s |
| `--main` | Funciona; acepta 18.844 dominios de 20.000 | 23,3 s |
| `--train full` / `--train tiny` | Funcionan (exactitud con el subconjunto: 0,973 / 0,928) | 1,5 s |
| `--secondary` | Funciona; acepta 15.832 dominios. Para el sondeo se copió `tranco-test2.dom` como `tranco-secondary.dom`, por el fallo C6 | 24,9 s |
| `--test_secondary full` | Funciona | 1,5 s |
| `--check` | Funciona con el modelo entrenado en el sondeo | 3,1 s |

Con `-W error::FutureWarning -W error::DeprecationWarning` (ignorando los avisos internos de nltk),
`--main`, `--train` y `--secondary` siguen funcionando: **pandas 3.0 y numpy 2 no avisan de nada** en este
código.

### Roturas y avisos encontrados

| # | Qué | Dónde | Tipo | Dónde se resuelve |
|---|---|---|---|---|
| 1 | `ModuleNotFoundError: No module named 'dns'`: el import de `dnspython` es obligatorio aunque solo lo use código muerto | `detectdga.py:10` | Rotura (en cuanto `dnspython` sale de los requisitos) | Ya prevista: tarea 5.1 (import perezoso) |
| 2 | `DeprecationWarning: datetime.datetime.utcfromtimestamp() is deprecated and scheduled for removal` | `DGAs/pizd.py:21` | Aviso; romperá en una versión futura de Python | Nueva casilla en 5.1. Debe mantener la instantánea idéntica |
| 3 | `ResourceWarning: unclosed file`, por `pickle.dump(sc, open(...))` sin cerrar | `detectdga.py:564`, `:571` | Aviso | En 5.2, al reescribir esas líneas para `skops` |
| 4 | `full.pkl` de 2021 no carga | `ml-data/full.pkl` | Rotura conocida (C2) | Fase 5 (reentrenar) |

**No se ha encontrado ninguna rotura de API** de pandas 3.0, numpy 2 ni scikit-learn 1.9 en el código. Los
`df.drop(..., inplace=True)` (`detectdga.py:524-549`) funcionan con pandas 3.0.

### Extrapolación del tiempo de reentrenamiento

Es una **hipótesis**: supone un coste lineal por dominio y no mide la memoria.

- `--main`: unos 1,0 ms por dominio, una vez descontados unos 3 s fijos de carga, sobre unos 2,95 M de líneas
  (1,5 M Tranco + 1,45 M de `dga.dom`) → **unos 50 min**.
- `--secondary` y Umbrella: alrededor de 1 M de dominios cada uno → **unos 17 min cada uno**.
- `--ngram` sobre 3,24 M de dominios: **pocos minutos**.
- `--train full` sobre unos 2,4 M de filas: el coste de un Random Forest no es lineal → **entre 5 y 15 min**.
- **Total estimado del reentrenamiento: entre 1,5 y 2 horas** en una máquina como la del sondeo. Se medirá de
  verdad en 5.4.

### Hallazgo colateral

Tres familias, **pizd, pykspa2 y suppobox, generan dominios distintos según la hora del día**. Sin `-d`, la
fecha es `datetime.now()` con hora, así que `-G`, `-C`, `-F` y la fuerza bruta dependen del momento en que se
ejecutan. Por eso `docs/MVP.md` §5 contó 1.784 dominios con `-F`, frente a los 1.794 con `-d 2026-10-18`.

Queda **fuera del alcance** de este documento: no es versiones ni datos. Las pruebas pasan siempre `-d`.
Hay que decidir si se trata como un error, el «día» que entiende el usuario frente a la marca de tiempo que
usa el algoritmo, cuando se aborde la fuerza bruta (`docs/FUTURE.md` §1.1.5).

### Hallazgo colateral 2: dependencia de la zona horaria (al probar la CI con `act`)

**pykspa2 y suppobox generan dominios distintos según la zona horaria de la máquina.** Usan `time.mktime`
(`DGAs/pykspa2.py:22`, `DGAs/suppobox.py:25`), que interpreta la fecha en hora local.

Para 2026-10-18, `lookdga.py -d 2026-10-18 -F` da:
- 1.784 dominios en UTC y en America/New_York;
- 1.794 en Europe/Madrid y en Asia/Tokyo.

Otros cinco módulos también usan `time.mktime` (`pykspa1`, `qadars`, `qsnatcha`, `qsnatchb`, `kraken2`). Para
esa fecha dan lo mismo en todas las zonas probadas; **hipótesis:** cambiarían cerca de los límites de su
periodo.

Consecuencias:
- un mismo dominio puede atribuirse o no por fuerza bruta según dónde se ejecute;
- la instantánea de las pruebas solo es reproducible con la zona horaria fija.

Las pruebas fijan `TZ=UTC` (`tests/conftest.py`), y la instantánea se regeneró en UTC; antes estaba en CEST.
Queda **fuera del alcance**, como el hallazgo anterior. Hay que decidir qué zona horaria es la correcta para
cada familia (la de la víctima, UTC…) cuando se aborde la fuerza bruta (`docs/FUTURE.md` §1.1.5). En Windows,
`time.tzset()` no existe. *Actualización 2026-10-20:* la instantánea pasa en la CI de Windows, pero sus
máquinas ya están en UTC, así que no prueba que `TZ=UTC` baste en un Windows con otra zona horaria (no
verificado).
