
export type Province = 'Almería' | 'Cádiz' | 'Córdoba' | 'Granada' | 'Huelva' | 'Jaén' | 'Málaga' | 'Sevilla';

export type Category = 'Gastronomía' | 'Patrimonio' | 'Fiestas' | 'Naturaleza';

export interface ChallengeIdea {
  id: number;
  province: Province;
  category: Category;
  title: string;
  description: string;
  epic?: boolean;
}

export interface RubricItem {
  criterion: string;
  points: number;
  description: string;
}
