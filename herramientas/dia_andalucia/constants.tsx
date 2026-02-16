
import React from 'react';
import { ChallengeIdea, RubricItem, Province, Category } from './types';

export const PROVINCES: Province[] = [
  'Almería', 'Cádiz', 'Córdoba', 'Granada', 'Huelva', 'Jaén', 'Málaga', 'Sevilla'
];

export const INFOGRAPHIC_RUBRIC: RubricItem[] = [
  { criterion: '1. Primera Impresión (Diseño)', points: 3, description: '¿Entra por los ojos? Colores bonitos, ordenado y dan ganas de mirarla.' },
  { criterion: '2. Las Imágenes', points: 3, description: '¡Fotones! Imagen central impactante y de muy buena calidad.' },
  { criterion: '3. El Texto (Lectura)', points: 3, description: 'Se lee volando. Frases cortas, letra grande y clara. Sin muros de texto.' },
  { criterion: '4. Contenido (Interés)', points: 3, description: '¡Qué curioso! He aprendido algo nuevo y el dato curioso me ha sorprendido.' },
  { criterion: '5. Coherencia y Errores', points: 3, description: 'Todo encaja. El texto tiene sentido, bien conectado y sin errores de tecleo.' },
];

export const VIDEO_RUBRIC: RubricItem[] = [
  { criterion: '1. Imagen y Estilo (Ojos)', points: 3, description: '¡Parece de cine! Imágenes de IA impresionantes y estilo (TikTok, documental) genial.' },
  { criterion: '2. Sonido y Voz (Oídos)', points: 3, description: 'Se escucha perfecto. Voz clara y música de fondo que no molesta.' },
  { criterion: '3. La Historia (Guion)', points: 3, description: '¡Me ha enganchado! Divertido y bien ordenado (principio y final).' },
  { criterion: '4. Contenido (Interés)', points: 3, description: 'He aprendido algo. El tema andaluz está bien explicado y con curiosidades.' },
  { criterion: '5. Ritmo (Duración)', points: 3, description: 'Se me ha pasado volando. Dura lo justo (menos de 2-5 min) y no es pesado.' },
];

export const IDEA_BANK: ChallengeIdea[] = [
  // ALMERÍA
  { id: 1, province: 'Almería', category: 'Naturaleza', title: 'El Desierto de Tabernas', description: 'El único desierto de Europa y escenario de mil películas.' },
  { id: 2, province: 'Almería', category: 'Patrimonio', title: 'El Indalo', description: '¿Qué significa este dibujo ancestral de nuestra tierra?' },
  { id: 3, province: 'Almería', category: 'Naturaleza', title: 'La Geoda de Pulpí', description: 'Cristales gigantes en una de las geodas más grandes del mundo.', epic: true },
  { id: 4, province: 'Almería', category: 'Patrimonio', title: 'La Alcazaba de Almería', description: 'La fortaleza que vigila el mar desde hace siglos.' },
  { id: 5, province: 'Almería', category: 'Naturaleza', title: 'Cabo de Gata', description: 'Playas volcánicas y paisajes vírgenes impresionantes.' },
  { id: 6, province: 'Almería', category: 'Patrimonio', title: 'Cine del Oeste', description: 'La historia del Spaghetti Western en los arenales de Almería.' },
  { id: 7, province: 'Almería', category: 'Naturaleza', title: 'Los invernaderos', description: 'El "mar de plástico" visto desde el espacio.' },
  { id: 8, province: 'Almería', category: 'Gastronomía', title: 'El tomate Raf', description: 'El rey de los tomates y el orgullo de la huerta almeriense.' },
  { id: 9, province: 'Almería', category: 'Patrimonio', title: 'Mojácar', description: 'La leyenda del pueblo blanco más bonito de la costa.' },
  { id: 10, province: 'Almería', category: 'Patrimonio', title: 'Catedral-Fortaleza', description: 'Una catedral única hecha para defenderse de piratas.' },
  { id: 11, province: 'Almería', category: 'Patrimonio', title: 'John Lennon en Almería', description: 'La curiosa historia de cuando un Beatle vivió aquí.' },
  // Fixed duplicate property error: removed duplicate and incorrect 'province: Gastronomía'
  { id: 12, province: 'Almería', category: 'Gastronomía', title: 'Cerámica de Níjar', description: 'Arte milenario en barro y color.' },

  // CÁDIZ
  { id: 13, province: 'Cádiz', category: 'Fiestas', title: 'Carnaval de Cádiz', description: 'Chirigotas, comparsas y el arte de la risa gaditana.', epic: true },
  { id: 14, province: 'Cádiz', category: 'Patrimonio', title: 'La Pepa', description: 'La Constitución de 1812: cuando Cádiz fue el centro del mundo.' },
  { id: 15, province: 'Cádiz', category: 'Naturaleza', title: 'Caballos Cartujanos', description: 'La elegancia de la raza de Jerez.' },
  { id: 16, province: 'Cádiz', category: 'Gastronomía', title: 'Atún de Almadraba', description: 'La pesca tradicional milenaria en las costas gaditanas.' },
  { id: 17, province: 'Cádiz', category: 'Patrimonio', title: 'Baelo Claudia', description: 'Ruinas romanas frente a la playa de Bolonia.' },
  { id: 18, province: 'Cádiz', category: 'Gastronomía', title: 'El "pescaíto" frito', description: 'El secreto del rebozado perfecto de la Bahía.' },
  { id: 19, province: 'Cádiz', category: 'Patrimonio', title: 'Los Pueblos Blancos', description: 'Setenil de las Bodegas y sus casas bajo las rocas.' },
  { id: 20, province: 'Cádiz', category: 'Naturaleza', title: 'Doñana (Cádiz)', description: 'La parte gaditana de la reserva más importante de Europa.' },
  { id: 21, province: 'Cádiz', category: 'Naturaleza', title: 'Industria de la sal', description: 'Las salinas y su importancia histórica en Cádiz.' },
  { id: 22, province: 'Cádiz', category: 'Fiestas', title: 'El Flamenco: Camarón', description: 'La leyenda de la Isla de San Fernando.' },
  { id: 23, province: 'Cádiz', category: 'Patrimonio', title: 'Castillo de San Sebastián', description: 'La fortaleza que protege la Caleta.' },
  { id: 24, province: 'Cádiz', category: 'Patrimonio', title: 'El faro de Trafalgar', description: 'Historia de la batalla naval más famosa.' },

  // CÓRDOBA
  { id: 25, province: 'Córdoba', category: 'Patrimonio', title: 'La Mezquita-Catedral', description: 'Un bosque de columnas único en el mundo.', epic: true },
  { id: 26, province: 'Córdoba', category: 'Fiestas', title: 'Los Patios de Córdoba', description: 'La explosión de flores y color del Festival de Mayo.' },
  { id: 27, province: 'Córdoba', category: 'Patrimonio', title: 'Medina Azahara', description: 'La ciudad brillante construida por Abderramán III.' },
  { id: 28, province: 'Córdoba', category: 'Gastronomía', title: 'El Salmorejo cordobés', description: 'Receta e historia del plato estrella de la ciudad.' },
  { id: 29, province: 'Córdoba', category: 'Patrimonio', title: 'El Puente Romano', description: 'El paso milenario sobre el río Guadalquivir.' },
  { id: 30, province: 'Córdoba', category: 'Patrimonio', title: 'La Judería', description: 'Callejas blancas, flores y la historia de Sefarad.' },
  { id: 31, province: 'Córdoba', category: 'Patrimonio', title: 'Julio Romero de Torres', description: 'El pintor que retrató el alma de la mujer cordobesa.' },
  { id: 32, province: 'Córdoba', category: 'Patrimonio', title: 'Cuero Cordobán', description: 'La artesanía milenaria de la piel.' },
  { id: 33, province: 'Córdoba', category: 'Patrimonio', title: 'Castillo de Almodóvar', description: 'El castillo de Juego de Tronos sobre el río.' },
  { id: 34, province: 'Córdoba', category: 'Gastronomía', title: 'Aceite de Baena', description: 'El oro líquido con denominación de origen.' },
  { id: 35, province: 'Córdoba', category: 'Fiestas', title: 'Manolete', description: 'La figura mítica del toreo cordobés.' },
  { id: 36, province: 'Córdoba', category: 'Patrimonio', title: 'Sinagoga de Córdoba', description: 'Una joya medieval escondida en la Judería.' },

  // GRANADA
  { id: 37, province: 'Granada', category: 'Patrimonio', title: 'La Alhambra', description: 'El palacio de los sueños nazaríes y sus leyendas.', epic: true },
  { id: 38, province: 'Granada', category: 'Patrimonio', title: 'El Generalife', description: 'Los jardines del agua y el descanso de los reyes.' },
  { id: 39, province: 'Granada', category: 'Patrimonio', title: 'Federico García Lorca', description: 'El poeta universal de Fuente Vaqueros.' },
  { id: 40, province: 'Granada', category: 'Naturaleza', title: 'Sierra Nevada', description: 'El Mulhacén y las cumbres más altas de la Península.' },
  { id: 41, province: 'Granada', category: 'Patrimonio', title: 'El barrio del Albaicín', description: 'Laberinto de calles blancas frente a la Alhambra.' },
  { id: 42, province: 'Granada', category: 'Patrimonio', title: 'Las cuevas del Sacromonte', description: 'Cuna del flamenco y las viviendas excavadas.' },
  { id: 43, province: 'Granada', category: 'Gastronomía', title: 'La Tortilla del Sacromonte', description: 'El plato más curioso y tradicional del barrio.' },
  { id: 44, province: 'Granada', category: 'Gastronomía', title: 'Los Piononos de Santa Fe', description: 'El dulce que rinde homenaje a un Papa.' },
  { id: 45, province: 'Granada', category: 'Patrimonio', title: 'La Reconquista', description: 'El final del Reino de Granada y los Reyes Católicos.' },
  { id: 46, province: 'Granada', category: 'Naturaleza', title: 'Parque de las Ciencias', description: 'La tecnología y la ciencia en el corazón de Andalucía.' },
  { id: 47, province: 'Granada', category: 'Naturaleza', title: 'La Alpujarra', description: 'Pueblos colgados de la montaña y aire puro.' },
  { id: 48, province: 'Granada', category: 'Fiestas', title: 'La Zambra', description: 'El baile flamenco más auténtico de Granada.' },

  // HUELVA
  { id: 49, province: 'Huelva', category: 'Patrimonio', title: 'Las Carabelas de Colón', description: 'Muelle de las Carabelas: donde empezó el viaje a América.' },
  { id: 50, province: 'Huelva', category: 'Gastronomía', title: 'Jamón de Jabugo', description: 'El pata negra más famoso del mundo.', epic: true },
  { id: 51, province: 'Huelva', category: 'Naturaleza', title: 'Parque de Doñana', description: 'El lince ibérico y el paraíso de las aves migratorias.' },
  { id: 52, province: 'Huelva', category: 'Naturaleza', title: 'La Gruta de las Maravillas', description: 'Un universo subterráneo en Aracena.' },
  { id: 53, province: 'Huelva', category: 'Fiestas', title: 'El Rocío', description: 'La romería más grande y famosa de España.' },
  { id: 54, province: 'Huelva', category: 'Naturaleza', title: 'Minas de Riotinto', description: 'El río rojo que parece el paisaje de Marte.' },
  { id: 55, province: 'Huelva', category: 'Gastronomía', title: 'La Gamba Blanca', description: 'El tesoro gastronómico del mar de Huelva.' },
  { id: 56, province: 'Huelva', category: 'Patrimonio', title: 'Juan Ramón Jiménez', description: 'El poeta de Moguer y su burrita "Platero".' },
  { id: 57, province: 'Huelva', category: 'Patrimonio', title: 'Niebla y su muralla', description: 'La fortaleza roja cargada de historia.' },
  { id: 58, province: 'Huelva', category: 'Gastronomía', title: 'El choco (sepia)', description: 'Por qué a los de Huelva se les llama choqueros.' },
  { id: 59, province: 'Huelva', category: 'Naturaleza', title: 'Playas vírgenes', description: 'Matalascañas y Mazagón: kilómetros de dunas.' },
  { id: 60, province: 'Huelva', category: 'Patrimonio', title: 'El Barrio Inglés', description: 'Arquitectura británica en el centro de Huelva.' },

  // JAÉN
  { id: 61, province: 'Jaén', category: 'Naturaleza', title: 'Mar de Olivos', description: 'Millones de árboles que bañan la provincia de verde.', epic: true },
  { id: 62, province: 'Jaén', category: 'Patrimonio', title: 'La Catedral de Jaén', description: 'La joya de Vandelvira que inspiró a las de América.' },
  { id: 63, province: 'Jaén', category: 'Patrimonio', title: 'Los Baños Árabes', description: 'Los más grandes y mejor conservados de España.' },
  { id: 64, province: 'Jaén', category: 'Patrimonio', title: 'Castillo de Santa Catalina', description: 'La cruz que vigila toda la ciudad desde el cerro.' },
  { id: 65, province: 'Jaén', category: 'Patrimonio', title: 'El Lagarto de Jaén', description: 'La leyenda más famosa: "¡Así revientes como el lagarto de Jaén!".' },
  { id: 66, province: 'Jaén', category: 'Patrimonio', title: 'Úbeda y Baeza', description: 'Ciudades Patrimonio de la Humanidad y joyas del Renacimiento.' },
  { id: 67, province: 'Jaén', category: 'Naturaleza', title: 'Cazorla, Segura y Las Villas', description: 'El parque natural más grande de España.' },
  { id: 68, province: 'Jaén', category: 'Naturaleza', title: 'Río Guadalquivir', description: 'El nacimiento del gran río en la Sierra de Cazorla.' },
  { id: 69, province: 'Jaén', category: 'Patrimonio', title: 'Batalla de las Navas de Tolosa', description: 'El choque que cambió la historia de España.' },
  { id: 70, province: 'Jaén', category: 'Patrimonio', title: 'Batalla de Bailén', description: 'Donde Napoleón sufrió su primera gran derrota.' },
  { id: 71, province: 'Jaén', category: 'Naturaleza', title: 'El lince ibérico', description: 'Sierra de Andújar: el último refugio del felino más amenazado.' },
  { id: 72, province: 'Jaén', category: 'Gastronomía', title: 'Aceituna de mesa', description: 'El arte del tapeo y el aliño jiennense.' },

  // MÁLAGA
  { id: 73, province: 'Málaga', category: 'Patrimonio', title: 'Alcazaba y Teatro Romano', description: 'El cruce de civilizaciones en el centro de la ciudad.' },
  { id: 74, province: 'Málaga', category: 'Patrimonio', title: 'Pablo Picasso', description: 'Vida y obra del genio malagueño más universal.', epic: true },
  { id: 75, province: 'Málaga', category: 'Gastronomía', title: 'Espetos de sardinas', description: 'El arte de asar al fuego en las barcas de la playa.' },
  { id: 76, province: 'Málaga', category: 'Naturaleza', title: 'Caminito del Rey', description: 'Un desfiladero de vértigo cargado de historia minera.' },
  { id: 77, province: 'Málaga', category: 'Patrimonio', title: 'La Farola de Málaga', description: 'El único faro con nombre femenino de España.' },
  { id: 78, province: 'Málaga', category: 'Patrimonio', title: 'Ronda y el Tajo', description: 'El puente nuevo sobre el abismo más famoso de Andalucía.' },
  { id: 79, province: 'Málaga', category: 'Naturaleza', title: 'La Cueva de Nerja', description: 'Pinturas rupestres y catedrales de estalactitas.' },
  { id: 80, province: 'Málaga', category: 'Patrimonio', title: 'Dólmenes de Antequera', description: 'Arquitectura de piedra de la prehistoria.' },
  { id: 81, province: 'Málaga', category: 'Patrimonio', title: 'La Biznaga', description: 'El jazmín convertido en arte y símbolo de Málaga.' },
  { id: 82, province: 'Málaga', category: 'Gastronomía', title: 'El Cenachero', description: 'El antiguo pescador que vendía por las calles.' },
  { id: 83, province: 'Málaga', category: 'Naturaleza', title: 'El Torcal de Antequera', description: 'El paisaje kárstico más alucinante de Europa.' },
  { id: 84, province: 'Málaga', category: 'Fiestas', title: 'Feria de Málaga', description: 'Cartojal, biznagas y alegría en las calles.' },

  // SEVILLA
  { id: 85, province: 'Sevilla', category: 'Patrimonio', title: 'La Giralda y el Giraldillo', description: 'El símbolo indiscutible del cielo sevillano.', epic: true },
  { id: 86, province: 'Sevilla', category: 'Patrimonio', title: 'Real Alcázar', description: 'Palacios árabes y jardines que parecen de otro mundo.' },
  { id: 87, province: 'Sevilla', category: 'Patrimonio', title: 'Torre del Oro', description: 'La torre que guardaba los tesoros del Guadalquivir.' },
  { id: 88, province: 'Sevilla', category: 'Patrimonio', title: 'Plaza de España', description: 'Obra maestra de Aníbal González y escenario de Star Wars.' },
  { id: 89, province: 'Sevilla', category: 'Fiestas', title: 'La Feria de Abril', description: 'Casetas, farolillos, albero y el arte del baile.' },
  { id: 90, province: 'Sevilla', category: 'Fiestas', title: 'Semana Santa de Sevilla', description: 'La pasión en la calle con los pasos y nazarenos.' },
  { id: 91, province: 'Sevilla', category: 'Patrimonio', title: 'Diego Velázquez', description: 'El pintor de reyes nacido en el barrio de la Alfalfa.' },
  { id: 92, province: 'Sevilla', category: 'Patrimonio', title: 'Gustavo Adolfo Bécquer', description: 'Rimas y Leyendas del poeta romántico por excelencia.' },
  { id: 93, province: 'Sevilla', category: 'Patrimonio', title: 'Barrio de Triana', description: 'Cerámica, marineros y la esencia del otro lado del río.' },
  { id: 94, province: 'Sevilla', category: 'Patrimonio', title: 'Itálica', description: 'La ciudad donde nacieron los emperadores Trajano y Adriano.' },
  { id: 95, province: 'Sevilla', category: 'Patrimonio', title: 'Archivo de Indias', description: 'Toda la historia de la llegada a América en un edificio.' },
  { id: 96, province: 'Sevilla', category: 'Gastronomía', title: 'El Gazpacho andaluz', description: 'La sopa fría más famosa nacida en el campo sevillano.' },

  // TEMAS GENERALES
  { id: 97, province: 'Sevilla', category: 'Fiestas', title: 'El Flamenco', description: 'Patrimonio de la Humanidad y el alma de Andalucía.' },
  { id: 98, province: 'Málaga', category: 'Patrimonio', title: 'Los Bandoleros', description: 'Leyendas de la Sierra y justicia en los caminos.' },
  { id: 99, province: 'Cádiz', category: 'Patrimonio', title: 'Pueblos Blancos', description: 'Por qué nuestras casas se pintan de cal blanca.' },
  { id: 100, province: 'Huelva', category: 'Patrimonio', title: 'Tartessos', description: 'En busca de la civilización perdida de Andalucía.' },
];
