const stage = process.env.SST_STAGE || "dev"

export default {
  url: stage === "production" ? "https://whykido.dev" : `https://${stage}.whykido.dev`,
  console: stage === "production" ? "https://whykido.dev/auth" : `https://${stage}.whykido.dev/auth`,
  email: "contact@whykido.dev",
  socialCard: "https://social-cards.sst.dev",
  github: "https://github.com/whykido/whykido",
  discord: "https://whykido.dev/discord",
  headerLinks: [
    { name: "Home", url: "/" },
    { name: "Docs", url: "/docs/" },
  ],
}
