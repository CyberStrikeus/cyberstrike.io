import { type TestimonialItem } from "../types/configDataTypes";
import placeholder from "@images/place-for-photo.png";

// Témoignages de la communauté - à mettre à jour avec de vrais témoignages
export const testimonialData: TestimonialItem[] = [
  {
    avatar: placeholder,
    name: "Alex Chen",
    title: "Ingénieur Sécurité Senior",
    testimonial: `Cyberstrike a réduit notre temps d'évaluation des vulnérabilités de 70%. L'IA comprend vraiment le contexte et ne vous bombarde pas de faux positifs.`,
  },
  {
    avatar: placeholder,
    name: "Sarah Mitchell",
    title: "Pentester",
    testimonial: `Enfin, un outil IA qui pense comme un pentester. La phase de reconnaissance seule me fait gagner des heures sur chaque mission.`,
  },
  {
    avatar: placeholder,
    name: "Marcus Rodriguez",
    title: "Consultant en Sécurité",
    testimonial: `Le modèle BYOK est brillant. Je garde le contrôle de mes coûts API et les données de mes clients restent privées. Gagnant-gagnant.`,
  },
  {
    avatar: placeholder,
    name: "Emily Watson",
    title: "Responsable Red Team",
    testimonial: `J'adore que ce soit open source. Nous l'avons forké, ajouté nos outils personnalisés, et maintenant nous avons un agent de pentest adapté à notre méthodologie.`,
  },
  {
    avatar: placeholder,
    name: "James Park",
    title: "Chasseur de Bug Bounty",
    testimonial: `Pouvoir basculer entre Claude et GPT-4 en cours de session est révolutionnaire. Différents modèles excellent dans différentes tâches.`,
  },
  {
    avatar: placeholder,
    name: "Lisa Thompson",
    title: "RSSI",
    testimonial: `Auto-hébergé, isolé, fonctionnant sur des modèles locaux. Parfait pour nos exigences de conformité. Et c'est complètement gratuit.`,
  },
];

export default testimonialData;
