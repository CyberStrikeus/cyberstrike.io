/**
 * Application-wide constants and configuration
 */
export const config = {
  // Base URL
  baseUrl: "https://cyberstrike.io",

  // GitHub
  github: {
    repoUrl: "https://github.com/CyberStrikeus/cyberstrike.io",
    starsFormatted: {
      compact: "0",
      full: "0",
    },
  },

  // Social links
  social: {
    twitter: "https://x.com/cyberstrike",
    discord: "https://cyberstrike.io/discord",
  },

  // Static stats (used on landing page)
  stats: {
    contributors: "0",
    commits: "0",
    monthlyUsers: "0",
  },
} as const
