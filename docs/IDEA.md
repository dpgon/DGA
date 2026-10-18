# DGA: la idea del proyecto

> Este documento separa siempre dos cosas:
> **[existe]** es una intención que ya está en el repositorio y se puede comprobar en él (ver `docs/ESTUDIO.md`).
> **[nuevo]** es una decisión tomada en octubre de 2026 durante la puesta a punto, que todavía no está construida.

---

## Propósito

DGA es un laboratorio abierto para entender y reconocer los dominios que el malware fabrica de forma
automática para comunicarse con sus servidores. Reúne decenas de algoritmos de generación de dominios (DGA)
de familias reales, que se pueden ejecutar para ver qué dominios producirían en cualquier fecha. Incluye
además un detector basado en aprendizaje automático, que dice si un dominio parece fabricado por una máquina
o elegido por una persona. Cuando parece fabricado, el laboratorio intenta averiguar qué familia lo generó,
qué día y en qué posición. Nació como trabajo de un máster de análisis de malware y reversing. Su objetivo
ahora es que cualquiera que lo encuentre en GitHub pueda aprender con él, reproducir el estudio y comprobar
por sí mismo que el enfoque sigue funcionando con malware actual.

## Problema y contexto

Muchas familias de malware no llevan escrita la dirección de su servidor de control. Llevan un algoritmo que
genera cada día una lista de dominios posibles, y el atacante registra solo uno. Bloquear dominios uno a uno
no sirve. Para defenderse hay que conocer el algoritmo, y así anticipar sus dominios, o reconocer en un nombre
de dominio la huella de que lo ha fabricado una máquina.

La información para hacerlo existe, pero está dispersa. Las reimplementaciones de los algoritmos están en
repositorios de investigadores, los listados de dominios maliciosos en feeds públicos y los clasificadores en
artículos académicos. A quien estudia el tema le cuesta tenerlo todo junto: generar, reconocer, atribuir y
medir sobre los mismos datos, con resultados que pueda repetir. DGA lo junta en un solo lugar **[existe]**.

Hoy, sin embargo, el proyecto no cumple su promesa de reproducibilidad. Sus datos y métricas son de 2021,
parte de la evaluación se solapa con el entrenamiento y no hay ninguna cifra de precisión publicada. Por eso
tampoco puede demostrar que sigue siendo útil frente a familias recientes. Resolverlo es el motivo de esta
puesta a punto **[nuevo]**.

## Usuarios objetivo

**[nuevo]** El público principal son quienes descubren el proyecto en GitHub con ánimo de aprender o evaluar:

- **Estudiantes y docentes de análisis de malware.** Quieren entender cómo funcionan los DGA, ver ejemplos
  reales y usarlos en clase o en prácticas. Su nivel es intermedio: manejan la terminal y conocen lo básico
  del malware, pero no tienen por qué saber de aprendizaje automático.
- **Investigadores y aficionados a la ciberseguridad.** Quieren reproducir el estudio, comparar variantes del
  detector o reutilizar el catálogo de algoritmos y los datos. Su nivel es avanzado.
- **Quien evalúa el trabajo del autor** (selección de personal, comunidad). Quiere comprobar en pocos minutos
  que el proyecto funciona, qué consigue y con qué honestidad presenta sus límites.

Los analistas de SOC o de respuesta a incidentes pueden encontrarle utilidad, pero **no son el público al
que se dirige** ni tienen garantías de soporte (ver No objetivos).

## Funcionalidad principal

### 1. Catálogo de algoritmos DGA

- **[existe]** 50 variantes de 38 familias (Banjori, Locky, Necurs, Qakbot, Zloader…), cada una con su ficha:
  descripción, referencias, cada cuántos días cambia, semillas conocidas, cuántos dominios genera por fecha,
  TLD posibles y patrón de sus dominios.
- **[existe]** Generar los dominios de una o varias familias para una fecha y una semilla dadas.
- **[existe]** Crear un corpus etiquetado (dominio, familia, semilla, fecha) con un número fijo de
  dominios por familia.
- **[existe]** Generar una lista de dominios de todas las familias para hoy y la semana siguiente, pensada
  para bloquearlos.
- **[nuevo]** Incorporar familias recientes solo cuando su algoritmo ya esté publicado por terceros.
- **[nuevo]** Comprobar que cada algoritmo reproduce fielmente los dominios de su referencia.

### 2. Reconocimiento y atribución de un dominio

- **[existe]** Decir qué familias podrían haber generado un dominio, según el patrón de cada una.
- **[existe]** Confirmar por fuerza bruta la familia, la semilla, el día y la posición en que se generó,
  buscando hacia atrás en el tiempo.
- **[nuevo]** Que el reconocimiento por patrón sea fiable, sin coincidencias más laxas de lo que promete.
- **[nuevo]** Que los límites de la búsqueda (cuántas posiciones y cuántos días se exploran) estén claros
  para el usuario y se puedan ajustar desde todas las vías de uso.

### 3. Detector de dominios generados

- **[existe]** Clasificar uno o varios dominios como «generado» o «humano» con el modelo ya entrenado que
  incluye el proyecto. Si sale «generado», encadenar la atribución del área 2.
- **[nuevo]** Recibir los dominios también desde un fichero o una lista y exportar los resultados para
  analizarlos aparte.
- **[nuevo]** Que cada veredicto corresponda siempre al dominio que se analizó, y que el usuario sepa qué
  dominios no se han podido evaluar y por qué.

### 4. Banco de investigación y evaluación

- **[existe]** Reconstruir los datos y reentrenar el detector desde las fuentes originales.
- **[existe]** Comparar variantes del detector según la información que usan (solo n-gramas, sin sílabas,
  versión reducida «tiny»…).
- **[existe]** Evaluar el detector con conjuntos de prueba aparte.
- **[existe]** Estudiar estadísticamente cada familia frente a dominios legítimos: topes de dominios por
  fecha, colisiones, alfabeto, letras dobles y repetidas, proporción de vocales y dígitos, sílabas,
  n-gramas.
- **[nuevo]** Evaluar con conjuntos de prueba realmente independientes del entrenamiento y publicar las
  métricas resultantes.
- **[nuevo]** Entrenar y evaluar con dominios DGA recientes de fuentes públicas, y medir cuánto había
  envejecido el modelo de 2021.
- **[nuevo]** Reparar todas las piezas secundarias que hoy fallan o no se usan, conservando el conjunto
  completo.

### 5. De la muestra a los dominios

- **[existe, sin uso]** El proyecto incluye reglas YARA de la mayoría de las familias, pero solo las cita.
- **[nuevo]** Dada una muestra sospechosa, identificar su familia mediante esas reglas y, a partir de ella,
  ofrecer su ficha y generar sus dominios. Así se cierra el camino que va del binario a la lista de bloqueo.

## Recorridos clave del usuario

### A. «¿Este dominio es malicioso, y de quién?»

1. El usuario tiene uno o varios dominios sospechosos: los escribe o, **[nuevo]**, aporta un fichero con
   ellos.
2. El detector devuelve para cada uno «generado» o «humano» e indica cuáles no ha podido evaluar.
3. Para los «generados», muestra las familias cuyo patrón encaja.
4. Si lo pide, el laboratorio confirma por fuerza bruta la familia, la semilla, el día y la posición.
5. **[nuevo]** El usuario exporta los resultados.

### B. «Quiero ver cómo piensa una familia»

1. El usuario lista las familias disponibles y abre la ficha de una.
2. Genera sus dominios para hoy o para una fecha concreta, con una semilla conocida.
3. Compara con estadísticas cómo se diferencian esos dominios de los legítimos.
4. Si lo necesita, genera la lista de bloqueo de la semana.

### C. «Quiero comprobar que el detector funciona de verdad» **[nuevo en su forma completa]**

1. El usuario instala el proyecto en un sistema actual siguiendo la documentación.
2. Ejecuta los ejemplos y obtiene los mismos resultados que publica el proyecto.
3. Reconstruye los datos y reentrena desde las fuentes indicadas.
4. Evalúa con conjuntos independientes, incluidos dominios DGA recientes, y obtiene métricas comparables a
   las publicadas.

### D. «Tengo una muestra, dame sus dominios» **[nuevo]**

1. El usuario aporta un fichero sospechoso.
2. El laboratorio lo identifica en estático, sin ejecutarlo, con las reglas de las familias.
3. Muestra la ficha de la familia y genera sus dominios para la fecha que elija.

## Principios del producto

**Los que el proyecto ya defiende** (se ven en sus decisiones) **[existe]**:

- **Entender antes que detectar.** Cada familia está reimplementada y documentada con sus referencias, y no
  se trata como una caja negra.
- **Atribuir, no solo clasificar.** El veredicto «generado» lleva hasta la familia, el día y la posición.
- **Reproducible desde las fuentes.** Todo el entrenamiento se puede rehacer a partir de datos públicos, y
  el resultado viene incluido para quien no quiera rehacerlo.
- **Local y autosuficiente.** Funciona en la terminal de quien lo usa, sin depender de servicios ajenos.
- **Reconocer el trabajo ajeno.** Cada algoritmo y cada regla citan su origen.

**Los que se quieren defender a partir de ahora** **[nuevo]**:

- **Honestidad sobre los resultados.** No se publica ninguna métrica que no se pueda reproducir, la
  evaluación nunca se solapa con el entrenamiento y los límites (familias antiguas, alcance de la fuerza
  bruta, dominios que no se evalúan) se dicen en voz alta.
- **Vigencia demostrada.** La utilidad se comprueba con dominios actuales, no se da por supuesta.
- **Funciona hoy, tal como dice.** La documentación y el comportamiento coinciden, y lo que se promete se
  puede ejecutar en un sistema actual.
- **Multiplataforma y sin conexión.** Funciona en Linux, macOS y Windows, y una vez instalado no necesita red.
  Es imprescindible para analizar muestras en máquinas aisladas.
- **Seguro de manejar.** Al analizar dominios o muestras de origen dudoso, el laboratorio nunca ejecuta lo
  que contienen.
- **Completo antes que recortado.** Se conservan y reparan todas las piezas del estudio original.

## No objetivos

- **No es un sistema de producción ni un servicio.** No monitoriza tráfico ni DNS en tiempo real y no
  ofrece servidor ni API remota.
- **No tiene interfaz gráfica ni demo web.** Se usa desde la terminal.
- **No bloquea nada por sí mismo.** Genera listas de dominios, pero aplicarlas es cosa del usuario.
- **No hace reversing nuevo.** Solo incorpora algoritmos que ya han publicado terceros.
- **No contacta con los dominios analizados.** No los resuelve ni se conecta a ellos.
- **No ejecuta muestras de malware.** La identificación por reglas es siempre estática.
- **No lee registros de DNS ni de proxy** en sus formatos nativos. Recibe listas de dominios.
- **No da soporte ni garantías** para uso operativo en entornos reales.
- **No pretende detectar cualquier DGA.** Su alcance son las familias que conoce y las que estén
  representadas en sus datos.

## Glosario del dominio

- **DGA (algoritmo de generación de dominios):** procedimiento con el que un malware calcula, a partir de la
  fecha y de una semilla, los dominios a los que intentará conectarse.
- **Familia:** malware concreto cuyo DGA se reproduce (p. ej. Tinba, Locky). Una familia puede tener varias
  **variantes** numeradas (`locky2`, `locky3`) cuando cambió su algoritmo.
- **Nombre corto:** identificador de la variante en el proyecto (`tinba`, `bazarbackdoor3`).
- **Semilla (seed):** valor que, junto con la fecha, determina los dominios generados. El proyecto llama
  **configuraciones (configs)** a las semillas conocidas de cada familia.
- **Fecha de generación y periodo:** día para el que se calculan los dominios. El periodo es cada cuántos
  días cambia la lista; algunas familias no dependen de la fecha.
- **Muestras por fecha (samples):** máximo de dominios distintos que una familia genera para una misma fecha.
- **Posición:** lugar que ocupa un dominio en la secuencia generada para una fecha.
- **TLD / terminaciones (ends):** sufijos finales que usa cada familia (`.com`, `.net`…).
- **SLD:** la parte del dominio inmediatamente anterior al sufijo, la que se analiza para decidir si es
  generada.
- **Patrón (regex):** descripción de la forma que tienen los dominios de una familia, con la que se
  sospecha de ella.
- **Detección:** sospechar qué familias encajan con un dominio por su patrón.
- **Fuerza bruta:** regenerar dominios de las familias sospechosas, fecha a fecha y semilla a semilla, hasta
  encontrar el dominio exacto, lo que confirma la atribución.
- **Lista de cortafuegos (firewall):** dominios de todas las familias para hoy y la semana siguiente.
- **Corpus:** colección de dominios etiquetados con su familia, semilla y fecha.
- **N-grama:** secuencia de 1 a 4 letras consecutivas. Su frecuencia en dominios legítimos indica cuán
  «humano» suena un dominio.
- **Diccionario de n-gramas:** frecuencias de n-gramas aprendidas de una lista de dominios legítimos.
- **Tranco:** ranking público de dominios legítimos populares, usado como ejemplo de dominios humanos.
- **Alexa:** antiguo ranking de dominios populares, ya retirado, que el proyecto usa como segundo conjunto de
  prueba.
- **Conjunto principal, secundario y Alexa:** datos para entrenar (principal) y para evaluar (secundario,
  con DGA generados por el propio proyecto; Alexa, con dominios legítimos).
- **Modelo full, ngram, nongram, nosyll, nongramnosyll, tiny:** variantes del detector según qué
  información del dominio tienen en cuenta.
- **Regla YARA:** firma que reconoce una familia de malware en un fichero.

## De dónde sale este documento

Este documento no se escribió antes de construir el proyecto. Se ha reconstruido en octubre de 2026 a partir
del código (resumido en `docs/ESTUDIO.md`) y de una conversación con el autor.

- Todo lo marcado **[existe]** se puede comprobar en el repositorio.
- Todo lo marcado **[nuevo]** son decisiones del autor en esa conversación: el público, el criterio de éxito,
  el tratamiento de las familias recientes, el uso de YARA, las plataformas y la entrada por fichero.
- Son **interpretación** del redactor:
  - el problema y su contexto;
  - los principios que el proyecto «ya defiende», deducidos de sus decisiones y no escritos por el autor;
  - la redacción de los no objetivos. Se propusieron al autor y él no puso objeciones, pero no los confirmó
    uno a uno.
