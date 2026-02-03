const stage = process.env.SST_STAGE || "dev"

export default {
  url: stage === "production" ? "https://cyberstrike.io" : `https://${stage}.cyberstrike.io`,
  console: stage === "production" ? "https://cyberstrike.io/auth" : `https://${stage}.cyberstrike.io/auth`,
  email: "contact@cyberstrike.io",
  socialCard: "https://social-cards.sst.dev",
  github: "https://github.com/CyberStrikeus/cyberstrike.io",
  discord: "https://cyberstrike.io/discord",
  headerLinks: [
    { name: "Home", url: "/" },
    { name: "Docs", url: "/docs/" },
  ],
}
