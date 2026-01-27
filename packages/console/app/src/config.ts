/**
 * Application-wide constants and configuration
 */
export const config = {
  // Base URL
  baseUrl: "https://whykido.dev",

  // GitHub
  github: {
    repoUrl: "https://github.com/whykido/whykido",
    starsFormatted: {
      compact: "0",
      full: "0",
    },
  },

  // Social links
  social: {
    twitter: "https://x.com/whykido",
    discord: "https://whykido.dev/discord",
  },

  // Static stats (used on landing page)
  stats: {
    contributors: "0",
    commits: "0",
    monthlyUsers: "0",
  },
} as const
