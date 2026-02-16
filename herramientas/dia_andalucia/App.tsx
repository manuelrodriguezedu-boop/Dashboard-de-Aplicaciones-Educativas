
import React, { useState, useEffect } from 'react';
import { 
  Trophy, 
  Map as MapIcon, 
  Lightbulb, 
  Rocket, 
  CheckCircle, 
  Mail, 
  Info, 
  Search,
  Zap,
  Palette,
  Video,
  ChevronDown,
  Layout,
  Pencil,
  Heart,
  ExternalLink,
  Star,
  Download,
  Menu,
  X
} from 'lucide-react';
import { PROVINCES, IDEA_BANK, INFOGRAPHIC_RUBRIC, VIDEO_RUBRIC } from './constants';
import { Province, Category, ChallengeIdea } from './types';

// --- Helper Functions ---

const scrollToSection = (id: string) => {
  const element = document.getElementById(id);
  if (element) {
    const offset = 90; // Height of navbar + extra spacing
    const elementPosition = element.getBoundingClientRect().top;
    const offsetPosition = elementPosition + window.pageYOffset - offset;

    window.scrollTo({
      top: offsetPosition,
      behavior: 'smooth'
    });
    
    // Update URL without jumping
    window.history.pushState(null, '', `#${id}`);
  }
};

// --- Components ---

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { name: 'La Misión', id: 'mision' },
    { name: 'Cómo Jugar', id: 'pasos' },
    { name: 'Banco de Ideas', id: 'ideas' },
    { name: 'Evaluación', id: 'evaluacion' },
  ];

  const handleLinkClick = (e: React.MouseEvent, id: string) => {
    e.preventDefault();
    scrollToSection(id);
    setIsOpen(false);
  };

  return (
    <nav className={`fixed top-0 left-0 right-0 z-[100] transition-all duration-300 ${scrolled ? 'bg-white/95 shadow-lg backdrop-blur-md py-2' : 'bg-white py-4'} border-b border-slate-200`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16 items-center">
          <div className="flex items-center gap-2">
            <button 
              onClick={() => scrollToSection('top')}
              className="flex items-center gap-2 group cursor-pointer border-none bg-transparent p-0 outline-none"
            >
              <div className="w-10 h-10 bg-andalucia rounded-lg flex items-center justify-center text-white font-bold text-xl shadow-lg shadow-green-900/20 group-hover:scale-110 transition-transform">A</div>
              <span className="font-brand font-bold text-lg hidden sm:block tracking-tight text-slate-900">IES Sierra Filabres</span>
            </button>
          </div>
          
          {/* Desktop Links */}
          <div className="hidden md:flex gap-8 font-medium text-slate-600">
            {navLinks.map((link) => (
              <a 
                key={link.id}
                href={`#${link.id}`}
                onClick={(e) => handleLinkClick(e, link.id)}
                className="hover:text-andalucia transition-all py-2 border-b-2 border-transparent hover:border-andalucia cursor-pointer"
              >
                {link.name}
              </a>
            ))}
          </div>

          <div className="hidden md:block">
            <button 
              onClick={() => scrollToSection('entrega')}
              className="bg-andalucia text-white px-6 py-2 rounded-full font-bold hover:bg-green-700 transition-all shadow-md shadow-green-900/20 active:scale-95 cursor-pointer border-none outline-none"
            >
              ¡Entregar!
            </button>
          </div>

          {/* Mobile Menu Button */}
          <div className="md:hidden">
            <button 
              onClick={() => setIsOpen(!isOpen)}
              className="p-2 rounded-lg text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer border-none bg-transparent"
            >
              {isOpen ? <X size={28} /> : <Menu size={28} />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu */}
      <div className={`md:hidden absolute top-full left-0 right-0 transition-all duration-300 overflow-hidden ${isOpen ? 'max-h-96 opacity-100 border-t border-slate-100 bg-white shadow-xl' : 'max-h-0 opacity-0 pointer-events-none'}`}>
        <div className="px-4 pt-2 pb-6 space-y-1">
          {navLinks.map((link) => (
            <a
              key={link.id}
              href={`#${link.id}`}
              onClick={(e) => handleLinkClick(e, link.id)}
              className="block px-3 py-4 rounded-md text-base font-bold text-slate-700 hover:text-andalucia hover:bg-green-50 transition-colors cursor-pointer"
            >
              {link.name}
            </a>
          ))}
          <div className="pt-4 border-t border-slate-100 mt-2">
            <button
              onClick={() => { scrollToSection('entrega'); setIsOpen(false); }}
              className="block w-full text-center bg-andalucia text-white px-6 py-4 rounded-xl font-black text-lg shadow-lg cursor-pointer border-none outline-none"
            >
              ¡Entregar Proyecto!
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

const Hero = () => (
  <header id="top" className="relative pt-32 pb-20 overflow-hidden bg-gradient-to-br from-white via-slate-50 to-green-50">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 text-center">
      <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-green-100 text-andalucia font-bold text-sm mb-6 animate-pulse">
        <Star size={16} fill="currentColor" /> Proyecto: Descubriendo Andalucía
      </div>
      <h1 className="text-5xl md:text-8xl font-brand font-black text-slate-900 mb-6 leading-tight tracking-tighter">
        Gincana Digital <br />
        <span className="text-andalucia">28 de Febrero</span>
      </h1>
      <p className="text-xl text-slate-600 max-w-2xl mx-auto mb-10 font-medium">
        Usa la Inteligencia Artificial para crear pósters visuales y vídeos increíbles sobre nuestra tierra. ¡Participa y gana!
      </p>
      <div className="flex flex-col sm:flex-row gap-4 justify-center">
        <button 
          onClick={() => scrollToSection('ideas')}
          className="px-10 py-5 bg-andalucia text-white rounded-2xl font-black text-xl shadow-xl shadow-green-900/20 hover:scale-105 transition-all flex items-center justify-center gap-2 cursor-pointer border-none outline-none"
        >
          Ver las 100 Ideas <MapIcon size={24} />
        </button>
        <button 
          onClick={() => scrollToSection('pasos')}
          className="px-10 py-5 bg-white text-slate-900 border-2 border-slate-200 rounded-2xl font-black text-xl hover:border-andalucia transition-all flex items-center justify-center gap-2 cursor-pointer outline-none"
        >
          ¿Cómo empiezo? <Rocket size={24} />
        </button>
      </div>
    </div>
    
    <div className="absolute -top-24 -left-24 w-64 h-64 bg-green-100 rounded-full blur-3xl opacity-60 pointer-events-none"></div>
    <div className="absolute -bottom-24 -right-24 w-64 h-64 bg-green-200 rounded-full blur-3xl opacity-60 pointer-events-none"></div>
  </header>
);

const MissionSection = () => (
  <section id="mision" className="py-24 bg-white relative">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="grid md:grid-cols-2 gap-16 items-center">
        <div>
          <h2 className="text-4xl font-brand font-bold mb-6">El Desafío de Andalucía</h2>
          <p className="text-lg text-slate-600 mb-8 leading-relaxed">
            No vamos a hacer un trabajo tradicional. Vamos a usar <span className="text-andalucia font-bold">NotebookLM</span>, la herramienta más potente de Google, para transformar fuentes históricas en contenido digital del siglo XXI.
          </p>
          
          <div className="space-y-6">
            <div className="flex gap-5 items-start p-6 rounded-2xl bg-slate-50 border border-slate-100">
              <div className="w-12 h-12 rounded-xl bg-purple-100 text-purple-600 flex-shrink-0 flex items-center justify-center">
                <Palette size={24} />
              </div>
              <div>
                <h4 className="font-bold text-xl">Concurso Infografías</h4>
                <p className="text-slate-500">Crea un póster visual automático con el botón morado. ¡Usa el lápiz para darle tu estilo!</p>
              </div>
            </div>
            <div className="flex gap-5 items-start p-6 rounded-2xl bg-slate-50 border border-slate-100">
              <div className="w-12 h-12 rounded-xl bg-blue-100 text-blue-600 flex-shrink-0 flex items-center justify-center">
                <Video size={24} />
              </div>
              <div>
                <h4 className="font-bold text-xl">Concurso Vídeos</h4>
                <p className="text-slate-500">Genera un vídeo corto con música y voz. ¡Ajusta el tono para que sea épico o divertido!</p>
              </div>
            </div>
          </div>
        </div>
        <div className="relative group">
          <div className="absolute -inset-1 bg-gradient-to-r from-green-600 to-green-400 rounded-3xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200 pointer-events-none"></div>
          <div className="relative aspect-[4/3] bg-slate-100 rounded-2xl overflow-hidden shadow-2xl">
            <img 
              src="https://images.unsplash.com/photo-1555881400-74d7acaacd8b?auto=format&fit=crop&q=80&w=800" 
              alt="Andalucía" 
              className="w-full h-full object-cover grayscale-[20%] group-hover:grayscale-0 transition-all duration-500"
            />
            <div className="absolute top-4 left-4">
              <div className="bg-white/90 backdrop-blur px-4 py-2 rounded-full font-black text-andalucia shadow-lg flex items-center gap-2">
                <Heart size={16} fill="currentColor" /> Patrimonio Andaluz
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
);

const WorkflowStep = ({ number, title, description, icon, colorClass, items }: any) => (
  <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm relative overflow-hidden">
    <div className={`absolute top-0 right-0 p-8 text-8xl font-black opacity-[0.03] ${colorClass.replace('bg-', 'text-')} pointer-events-none`}>
      {number}
    </div>
    <div className={`w-16 h-16 rounded-2xl ${colorClass} text-white flex items-center justify-center mb-8 shadow-lg`}>
      {icon}
    </div>
    <h3 className="text-2xl font-brand font-bold mb-4">Paso {number}: {title}</h3>
    <p className="text-slate-600 mb-8 leading-relaxed font-medium">{description}</p>
    <div className="space-y-3">
      {items.map((item: string, i: number) => (
        <div key={i} className="flex gap-3 items-center p-3 rounded-xl bg-slate-50 border border-slate-100 text-sm font-bold text-slate-700">
          <CheckCircle size={16} className="text-andalucia" />
          {item}
        </div>
      ))}
    </div>
  </div>
);

const Workflow = () => (
  <section id="pasos" className="py-24 bg-slate-50">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-16">
        <h2 className="text-4xl font-brand font-bold mb-4">Instrucciones de la Misión</h2>
        <p className="text-slate-600 max-w-2xl mx-auto font-medium">No necesitas saber programar ni ser diseñador. La IA de NotebookLM será tu herramienta mágica.</p>
      </div>
      
      <div className="grid lg:grid-cols-3 gap-8">
        <WorkflowStep 
          number="1"
          title="Elige tu Misión"
          icon={<MapIcon size={32} />}
          colorClass="bg-green-600"
          description="Selecciona UNA provincia y UN tema. No hables de todo, busca algo concreto que te apasione."
          items={["Elige 1 de las 100 Ideas", "Apunta tu provincia y tema", "Misión Épica = Más puntos"]}
        />
        <WorkflowStep 
          number="2"
          title="El Botón Mágico"
          icon={<Zap size={32} />}
          colorClass="bg-purple-600"
          description="Sube tus fuentes a NotebookLM y usa los botones de color morado o azul del panel 'STUDIO'."
          items={["Sube PDFs o enlaces", "Botón Infografía (Morado)", "Botón Vídeo (Azul)"]}
        />
        <WorkflowStep 
          number="3"
          title="Edita y Personaliza"
          icon={<Pencil size={32} />}
          colorClass="bg-pink-600"
          description="¡No lo dejes como sale! Usa el botón de lápiz (Editar) para cambiar el estilo o el narrador."
          items={["Usa el Lápiz (Editar)", "Prueba 'Estilo de Cómic'", "Guarda y envía por correo"]}
        />
      </div>
    </div>
  </section>
);

const IdeaBank = () => {
  const [filter, setFilter] = useState<Province | 'Todas'>('Todas');
  const [categoryFilter, setCategoryFilter] = useState<Category | 'Todas'>('Todas');
  const [showAll, setShowAll] = useState(false);
  
  const filteredIdeas = IDEA_BANK.filter(idea => 
    (filter === 'Todas' || idea.province === filter) &&
    (categoryFilter === 'Todas' || idea.category === categoryFilter)
  );

  const visibleIdeas = showAll ? filteredIdeas : filteredIdeas.slice(0, 16);

  return (
    <section id="ideas" className="py-24 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-8 mb-16">
          <div className="max-w-xl">
            <h2 className="text-5xl font-brand font-bold mb-6">Anexo: 100 Ideas</h2>
            <p className="text-slate-600 text-lg font-medium">¿No sabes qué elegir? Aquí tienes 100 ideas clasificadas para tu infografía o vídeo. ¡Elige la que más te guste!</p>
          </div>
          <div className="flex flex-wrap gap-4">
            <select 
              value={filter} 
              onChange={(e) => setFilter(e.target.value as any)}
              className="bg-slate-100 border-none px-6 py-4 rounded-2xl font-black text-slate-800 focus:ring-4 focus:ring-andalucia/20 outline-none transition-all shadow-sm cursor-pointer"
            >
              <option value="Todas">🌍 Todas las Provincias</option>
              {PROVINCES.map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <select 
              value={categoryFilter} 
              onChange={(e) => setCategoryFilter(e.target.value as any)}
              className="bg-slate-100 border-none px-6 py-4 rounded-2xl font-black text-slate-800 focus:ring-4 focus:ring-andalucia/20 outline-none transition-all shadow-sm cursor-pointer"
            >
              <option value="Todas">💡 Todas las Categorías</option>
              <option value="Gastronomía">🍳 Gastronomía</option>
              <option value="Patrimonio">🏰 Patrimonio</option>
              <option value="Fiestas">💃 Fiestas</option>
              <option value="Naturaleza">🌿 Naturaleza</option>
            </select>
          </div>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {visibleIdeas.map((idea) => (
            <div key={idea.id} className="group p-8 rounded-3xl bg-slate-50 border border-slate-100 hover:border-andalucia/30 transition-all hover:shadow-2xl hover:-translate-y-2 relative overflow-hidden">
              {idea.epic && (
                <div className="absolute -top-1 -right-1 pointer-events-none">
                  <div className="bg-amber-400 text-amber-950 text-[10px] font-black px-4 py-1 rounded-bl-xl rotate-0 shadow-lg flex items-center gap-1 uppercase tracking-tighter">
                    <Trophy size={10} /> Misión Épica
                  </div>
                </div>
              )}
              <div className="flex justify-between items-start mb-6">
                <span className={`px-4 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest ${
                  idea.category === 'Gastronomía' ? 'bg-orange-100 text-orange-600' :
                  idea.category === 'Patrimonio' ? 'bg-blue-100 text-blue-600' :
                  idea.category === 'Fiestas' ? 'bg-pink-100 text-pink-600' :
                  'bg-green-100 text-green-600'
                }`}>
                  {idea.category}
                </span>
              </div>
              <h4 className="text-xl font-black mb-3 leading-tight group-hover:text-andalucia transition-colors">{idea.title}</h4>
              <p className="text-sm text-slate-500 mb-6 font-medium leading-relaxed">{idea.description}</p>
              <div className="flex items-center gap-2 text-xs font-black text-slate-400 uppercase tracking-widest border-t border-slate-200 pt-4">
                <MapIcon size={14} className="text-andalucia" /> {idea.province}
              </div>
            </div>
          ))}
        </div>
        
        <div className="mt-16 text-center">
          <button 
            onClick={() => setShowAll(!showAll)}
            className="px-10 py-5 bg-slate-900 text-white rounded-2xl font-black text-lg hover:bg-slate-800 transition-all shadow-xl shadow-slate-900/20 cursor-pointer border-none outline-none"
          >
            {showAll ? 'Mostrar menos ideas' : `Ver las ${filteredIdeas.length} ideas de este filtro`}
          </button>
        </div>
      </div>
    </section>
  );
};

const Evaluation = () => {
  const [activeTab, setActiveTab] = useState<'infog' | 'video'>('infog');

  return (
    <section id="evaluacion" className="py-24 bg-slate-900 text-white overflow-hidden relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="text-center mb-16">
          <h2 className="text-5xl font-brand font-bold mb-6">Hojas de Jurado ⚖️</h2>
          <p className="text-slate-400 max-w-2xl mx-auto text-lg font-medium">¿Qué evaluamos? Así es como los expertos puntuarán tu trabajo. ¡Apunta al 3!</p>
        </div>

        <div className="flex justify-center mb-12">
          <div className="bg-white/10 backdrop-blur p-2 rounded-2xl inline-flex">
            <button 
              onClick={() => setActiveTab('infog')}
              className={`px-8 py-3 rounded-xl font-black text-lg transition-all cursor-pointer border-none outline-none ${activeTab === 'infog' ? 'bg-andalucia text-white shadow-lg' : 'text-slate-400 hover:text-white bg-transparent'}`}
            >
              Infografías
            </button>
            <button 
              onClick={() => setActiveTab('video')}
              className={`px-8 py-3 rounded-xl font-black text-lg transition-all cursor-pointer border-none outline-none ${activeTab === 'video' ? 'bg-andalucia text-white shadow-lg' : 'text-slate-400 hover:text-white bg-transparent'}`}
            >
              Vídeos
            </button>
          </div>
        </div>

        <div className="grid lg:grid-cols-5 gap-6 mb-16">
          <div className="bg-white/5 p-6 rounded-2xl border border-white/10 text-center">
            <span className="text-4xl block mb-2">🤩</span>
            <span className="font-black text-xl text-andalucia">3 Puntos</span>
            <p className="text-xs text-slate-400 uppercase font-black mt-2">¡Genial! (Excelente)</p>
          </div>
          <div className="bg-white/5 p-6 rounded-2xl border border-white/10 text-center">
            <span className="text-4xl block mb-2">🙂</span>
            <span className="font-black text-xl text-green-400">2 Puntos</span>
            <p className="text-xs text-slate-400 uppercase font-black mt-2">Está bien (Correcto)</p>
          </div>
          <div className="bg-white/5 p-6 rounded-2xl border border-white/10 text-center">
            <span className="text-4xl block mb-2">😐</span>
            <span className="font-black text-xl text-amber-400">1 Punto</span>
            <p className="text-xs text-slate-400 uppercase font-black mt-2">Regular (Mejorable)</p>
          </div>
          <div className="bg-white/5 p-6 rounded-2xl border border-white/10 text-center">
            <span className="text-4xl block mb-2">🤕</span>
            <span className="font-black text-xl text-red-400">0 Puntos</span>
            <p className="text-xs text-slate-400 uppercase font-black mt-2">Flojo (Deficiente)</p>
          </div>
          <div className="bg-andalucia p-6 rounded-2xl text-center flex flex-col justify-center">
            <span className="font-black text-2xl">Máximo 15</span>
            <p className="text-xs uppercase font-black mt-1 opacity-70">Puntuación Total</p>
          </div>
        </div>

        <div className="grid lg:grid-cols-1 gap-4">
          {(activeTab === 'infog' ? INFOGRAPHIC_RUBRIC : VIDEO_RUBRIC).map((item, idx) => (
            <div key={idx} className="flex flex-col md:flex-row gap-6 p-8 rounded-3xl bg-white/5 border border-white/10 hover:bg-white/10 transition-all items-center">
              <div className="w-16 h-16 rounded-2xl bg-white/10 flex items-center justify-center flex-shrink-0 text-3xl font-black">
                {idx + 1}
              </div>
              <div className="flex-grow">
                <h4 className="text-2xl font-black mb-2">{item.criterion}</h4>
                <p className="text-slate-400 text-lg">{item.description}</p>
              </div>
              <div className="text-right">
                <div className="text-3xl font-black text-andalucia">0 - 3</div>
                <div className="text-[10px] font-black uppercase text-slate-500 tracking-widest">Puntos posibles</div>
              </div>
            </div>
          ))}
        </div>
        
        <div className="mt-16 text-center">
          <button className="inline-flex items-center gap-3 px-10 py-5 bg-white text-slate-900 rounded-2xl font-black text-xl hover:scale-105 transition-transform shadow-2xl cursor-pointer border-none outline-none">
            <Download size={24} /> Descargar Hojas de Jurado (PDF)
          </button>
        </div>
      </div>
    </section>
  );
};

const SubmissionChecklist = () => {
  const [checks, setChecks] = useState({
    generated: false,
    quality: false,
    saved: false,
    filename: false,
    email: false
  });

  const toggleCheck = (id: string) => {
    setChecks(prev => ({ ...prev, [id]: !prev[id as keyof typeof prev] }));
  };

  const allChecked = Object.values(checks).every(v => v);

  return (
    <section id="entrega" className="py-24 bg-white relative">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-slate-50 rounded-3xl p-8 md:p-16 border-4 border-dashed border-slate-200">
          <div className="text-center mb-12">
            <span className="text-6xl mb-6 block">✅</span>
            <h2 className="text-4xl font-brand font-black mb-4 uppercase tracking-tighter">Lista de Repaso (Check-list)</h2>
            <p className="text-slate-600 font-bold">Mira tu trabajo y marca las casillas si lo has cumplido antes de enviar.</p>
          </div>
          
          <div className="space-y-4 mb-12">
            {[
              { id: 'generated', text: '¿He usado el botón de Infografía/Vídeo y generado un archivo final?' },
              { id: 'quality', text: '¿La obra se ve/escucha bien y se entiende el contenido?' },
              { id: 'saved', text: '¿He guardado el archivo correctamente en mi ordenador?' },
              { id: 'filename', text: '¿El nombre del archivo deja claro cuál es mi tema? (Ej: Aceite_Jaen.png)' },
              { id: 'email', text: '¿He enviado el correo adjunto a mrodpen150@g.educaand.es?' },
            ].map(item => (
              <button 
                key={item.id}
                onClick={() => toggleCheck(item.id)}
                className={`w-full flex items-center gap-6 p-6 rounded-2xl border-2 transition-all text-left shadow-sm cursor-pointer outline-none ${
                  checks[item.id as keyof typeof checks] 
                  ? 'bg-green-100 border-andalucia text-andalucia scale-[1.02]' 
                  : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300'
                }`}
              >
                <div className={`w-8 h-8 rounded-full border-4 flex items-center justify-center flex-shrink-0 transition-all ${
                  checks[item.id as keyof typeof checks] ? 'bg-andalucia border-andalucia text-white' : 'border-slate-200 bg-slate-50'
                }`}>
                  {checks[item.id as keyof typeof checks] && <CheckCircle size={20} />}
                </div>
                <span className="font-black text-lg">{item.text}</span>
              </button>
            ))}
          </div>

          <div className="text-center">
            <div className="bg-blue-50 p-8 rounded-3xl border border-blue-100 mb-10">
              <p className="text-blue-900 font-black text-xl mb-2 flex items-center justify-center gap-2">
                <Mail className="text-blue-600" /> Correo de entrega:
              </p>
              <code className="text-2xl font-black text-blue-700 bg-white px-4 py-2 rounded-lg border border-blue-200">mrodpen150@g.educaand.es</code>
            </div>
            
            <a 
              href={allChecked ? "mailto:mrodpen150@g.educaand.es" : "#"}
              onClick={(e) => !allChecked && e.preventDefault()}
              className={`inline-flex items-center gap-4 px-12 py-6 rounded-3xl font-black text-2xl shadow-2xl transition-all border-none no-underline ${
                allChecked 
                ? 'bg-andalucia text-white hover:scale-105 hover:bg-green-700 active:scale-95 cursor-pointer' 
                : 'bg-slate-300 text-slate-500 cursor-not-allowed opacity-50'
              }`}
            >
              ¡Misión Cumplida: Enviar! <Rocket />
            </a>
            {!allChecked && <p className="mt-6 text-sm font-black text-red-500 uppercase tracking-widest animate-bounce">Faltan puntos por revisar en el Check-list</p>}
          </div>
        </div>
      </div>
    </section>
  );
};

const Footer = () => (
  <footer className="bg-slate-900 py-16 text-white border-t border-white/5 relative z-10">
    <div className="max-w-7xl mx-auto px-4 text-center">
      <div className="w-16 h-16 bg-andalucia rounded-2xl flex items-center justify-center text-white font-black text-3xl mx-auto mb-8 shadow-xl shadow-green-900/20">A</div>
      <h3 className="text-3xl font-brand font-black mb-2 tracking-tighter">Gincana Digital 2024</h3>
      <p className="text-slate-500 font-bold mb-8 uppercase tracking-widest text-sm">IES Sierra de los Filabres • Purchena</p>
      
      <div className="flex justify-center gap-6 mb-12">
        <div className="w-12 h-12 bg-white/5 rounded-full flex items-center justify-center hover:bg-andalucia transition-all cursor-pointer">
          <Heart size={20} />
        </div>
        <div className="w-12 h-12 bg-white/5 rounded-full flex items-center justify-center hover:bg-andalucia transition-all cursor-pointer">
          <Trophy size={20} />
        </div>
        <div className="w-12 h-12 bg-white/5 rounded-full flex items-center justify-center hover:bg-andalucia transition-all cursor-pointer">
          <Rocket size={20} />
        </div>
      </div>
      
      <div className="pt-8 border-t border-white/5 text-slate-600 font-bold text-xs uppercase tracking-widest">
        Día de Andalucía • Plan de Competencia Digital Educativa
      </div>
    </div>
  </footer>
);

export default function App() {
  return (
    <div className="min-h-screen selection:bg-andalucia selection:text-white bg-white">
      <Navbar />
      <main className="relative">
        <Hero />
        <MissionSection />
        <Workflow />
        <IdeaBank />
        <Evaluation />
        <SubmissionChecklist />
      </main>
      <Footer />
    </div>
  );
}
