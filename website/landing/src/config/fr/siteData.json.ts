import { type SiteDataProps } from "../types/configDataTypes";

// Informations du site
const siteData: SiteDataProps = {
  name: "Cyberstrike",
  // Titre et description du site (balises meta)
  title: "Cyberstrike - Agent de Test de Pénétration IA",
  description:
    "Cyberstrike est un agent IA autonome pour les tests de pénétration et la recherche en sécurité. Accédez à Claude, GPT, Gemini et plus via une interface CLI unifiée.",

  // Utilisé sur la page de contact et le footer
  contact: {
    address1: "",
    address2: "",
    phone: "",
    email: "contact@cyberstrike.io",
  },

  // Informations pour les articles de blog
  author: {
    name: "Cyberstrike",
    email: "contact@cyberstrike.io",
    twitter: "cyberstrike_io",
  },

  // Image par défaut pour les balises meta si la page n'a pas d'image
  defaultImage: {
    src: "/images/cyberstrike-og.png",
    alt: "Cyberstrike - Agent de Test de Pénétration IA",
  },
};

export default siteData;
