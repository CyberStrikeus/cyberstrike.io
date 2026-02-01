import { type SiteDataProps } from "../types/configDataTypes";

// Update this file with your site specific information
const siteData: SiteDataProps = {
  name: "Cyberstrike",
  // Your website's title and description (meta fields)
  title: "Cyberstrike - AI-Powered Penetration Testing Agent",
  description:
    "Cyberstrike is an autonomous AI agent for penetration testing and security research. Access Claude, GPT, Gemini and more through a unified CLI interface.",

  // used on contact page and footer
  contact: {
    address1: "",
    address2: "",
    phone: "",
    email: "contact@cyberstrike.io",
  },

  // Your information for blog post purposes
  author: {
    name: "Cyberstrike",
    email: "contact@cyberstrike.io",
    twitter: "cyberstrike_io",
  },

  // default image for meta tags if the page doesn't have an image already
  defaultImage: {
    src: "/images/cyberstrike-og.png",
    alt: "Cyberstrike - AI Penetration Testing Agent",
  },
};

export default siteData;
