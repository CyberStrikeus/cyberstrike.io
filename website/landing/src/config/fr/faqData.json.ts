import { type FaqItem } from "../types/configDataTypes";

export const faqData: FaqItem[] = [
  {
    question: "Qu'est-ce que Cyberstrike ?",
    answer: `Cyberstrike est un agent de test de pénétration autonome alimenté par l'IA. Il combine plusieurs modèles d'IA
    (Claude, GPT, Gemini) avec des outils de sécurité spécialisés pour effectuer des évaluations, identifier les vulnérabilités
    et générer des rapports détaillés - le tout avec une intervention humaine minimale. Il est 100% open source sous licence AGPL-3.0.`,
  },
  {
    question: "Comment fonctionne le modèle BYOK (Bring Your Own Key) ?",
    answer: `Avec BYOK, vous utilisez vos propres clés API des fournisseurs d'IA comme Anthropic, OpenAI ou Google.
    Cela signifie que vous avez un contrôle total sur vos coûts d'IA, vos limites d'utilisation et la confidentialité de vos données.
    Nous ne stockons jamais et n'avons jamais accès à vos conversations avec les modèles d'IA.`,
  },
  {
    question: "Cyberstrike est-il sûr à utiliser sur des systèmes de production ?",
    answer: `Cyberstrike est conçu uniquement pour les tests de sécurité autorisés. Il inclut des mécanismes de sécurité intégrés
    et nécessite une confirmation explicite avant d'effectuer toute action potentiellement destructrice.
    Assurez-vous toujours d'avoir l'autorisation appropriée avant de tester un système.`,
  },
  {
    question: "Quels modèles d'IA sont supportés ?",
    answer: `Cyberstrike supporte Claude (Anthropic), GPT-4 (OpenAI), Gemini (Google) et d'autres fournisseurs d'IA majeurs.
    Vous pouvez également utiliser des modèles locaux comme Ollama pour les environnements isolés.
    Changez de modèle selon vos besoins et préférences.`,
  },
  {
    question: "Puis-je auto-héberger Cyberstrike ?",
    answer: `Oui ! Cyberstrike est entièrement auto-hébergeable. Vous pouvez l'exécuter sur votre propre infrastructure,
    utiliser des modèles d'IA locaux avec Ollama et garder toutes les données sur site. Parfait pour les organisations
    ayant des exigences de sécurité strictes ou des environnements isolés.`,
  },
  {
    question: "Cyberstrike est-il gratuit ?",
    answer: `Cyberstrike est open source sous licence AGPL-3.0. Pour un usage personnel, la recherche et l'éducation - c'est entièrement gratuit.
    Pour un usage commercial où vous ne souhaitez pas ouvrir vos modifications, nous proposons une licence commerciale.
    Contactez license@cyberstrike.io pour les options de licence entreprise.`,
  },
  {
    question: "Comment puis-je contribuer ?",
    answer: `Nous accueillons les contributions ! Consultez notre dépôt GitHub pour signaler des problèmes, soumettre des pull requests
    ou rejoindre les discussions. Que ce soit du code, de la documentation ou des intégrations d'outils de sécurité - toutes les contributions
    aident à améliorer Cyberstrike pour la communauté de la sécurité.`,
  },
];

export default faqData;
