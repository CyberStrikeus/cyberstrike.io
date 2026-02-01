import { type teamMember } from "@config/types/configDataTypes";
import member1 from "@images/nic_fassbender.jpg";
import member2 from "@images/ashton_blackwell.jpg";
import member3 from "@images/nicola_harris.jpg";

export const teamData: teamMember[] = [
  {
    image: member1,
    name: "Security Lead",
    title: "Ex-Expedia, Capital One",
    bio: `10+ years in offensive security. Led penetration testing teams at Fortune 500 companies.
      Specialized in web application security and cloud infrastructure assessments.
      OSCP, OSCE, CISSP certified.`,
  },
  {
    image: member2,
    name: "Principal Engineer",
    title: "Ex-MUFG, Bugcrowd",
    bio: `Former bug bounty program manager and security engineer.
      Built and scaled vulnerability disclosure platforms.
      Expert in automation and AI-assisted security testing.`,
  },
  {
    image: member3,
    name: "Research Lead",
    title: "Ex-HackerOne, Cobalt",
    bio: `500+ pentests delivered across financial services, healthcare, and tech sectors.
      Published security researcher with CVEs in major products.
      Focused on red team operations and adversary simulation.`,
  },
];

export default teamData;
