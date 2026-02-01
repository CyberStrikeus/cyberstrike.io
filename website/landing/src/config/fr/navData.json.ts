/**
 * * This file is used to define the navigation links for the site.
 * Notes:
 * 1 level of dropdown is supported
 * Mega menus look best with 3-5 columns, but supports anything > 2 columns
 * If using icons, the icon should be saved in the src/icons folder. If filename is "tabler/icon.svg" then input "tabler/icon"
 * Recommend getting icons from https://tabler.io/icons
 */

// types
import { type navItem } from "../types/configDataTypes";

// note: 1 level of dropdown is supported
const navConfig: navItem[] = [
  {
    text: "Fonctionnalités",
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
    text: "Ressources",
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
        text: "Politique de confidentialité",
        link: "/privacy-policy",
        icon: "tabler/lock",
      },
      {
        text: "Conditions d'utilisation",
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
