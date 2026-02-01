/**
 * * Navigation links for Cyberstrike
 */

import { type navItem } from "../types/configDataTypes";

const navConfig: navItem[] = [
  {
    text: "Features",
    link: "/features",
  },
  {
    text: "Open Source",
    link: "/#open-source",
  },
  {
    text: "Blog",
    link: "/blog",
  },
  {
    text: "Resources",
    dropdown: [
      {
        text: "FAQ",
        link: "/#faq-accordions",
        icon: "tabler/help",
      },
      {
        text: "GitHub",
        link: "https://github.com/CyberStrikeus/cyberstrike.io",
        icon: "tabler/brand-github",
      },
      {
        text: "Privacy Policy",
        link: "/privacy-policy",
        icon: "tabler/lock",
      },
      {
        text: "Terms of Use",
        link: "/terms",
        icon: "tabler/file-text",
      },
    ],
  },
  {
    text: "Docs",
    link: "https://docs.cyberstrike.io",
    newTab: true,
  },
];

export default navConfig;
