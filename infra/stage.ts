export const domain = (() => {
  if ($app.stage === "production") return "whykido.dev"
  if ($app.stage === "dev") return "dev.whykido.dev"
  return `${$app.stage}.dev.whykido.dev`
})()

// TODO: Update zone ID for whykido.dev domain
export const zoneID = "430ba34c138cfb5360826c4909f99be8"

new cloudflare.RegionalHostname("RegionalHostname", {
  hostname: domain,
  regionKey: "us",
  zoneId: zoneID,
})

export const shortDomain = (() => {
  if ($app.stage === "production") return "whykido.dev"
  if ($app.stage === "dev") return "dev.whykido.dev"
  return `${$app.stage}.dev.whykido.dev`
})()
