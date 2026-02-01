import { type teamMember } from "@config/types/configDataTypes";
import member1 from "@images/nic_fassbender.jpg";
import member2 from "@images/ashton_blackwell.jpg";
import member3 from "@images/nicola_harris.jpg";

export const teamData: teamMember[] = [
  {
    image: member1,
    name: "Security Lead",
    title: "Ex-Expedia, Capital One",
    bio: `10+ ans en sécurité offensive. A dirigé des équipes de tests de pénétration dans des entreprises Fortune 500.
      Spécialisé en sécurité des applications web et évaluations d'infrastructure cloud.
      Certifié OSCP, OSCE, CISSP.`,
  },
  {
    image: member2,
    name: "Principal Engineer",
    title: "Ex-MUFG, Bugcrowd",
    bio: `Ancien gestionnaire de programme bug bounty et ingénieur sécurité.
      A construit et mis à l'échelle des plateformes de divulgation de vulnérabilités.
      Expert en automatisation et tests de sécurité assistés par IA.`,
  },
  {
    image: member3,
    name: "Research Lead",
    title: "Ex-HackerOne, Cobalt",
    bio: `500+ pentests réalisés dans les secteurs financiers, santé et technologie.
      Chercheur en sécurité publié avec des CVEs dans des produits majeurs.
      Spécialisé en opérations red team et simulation d'adversaires.`,
  },
];

export default teamData;
