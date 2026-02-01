#!/usr/bin/env bun

import { $ } from "bun"
import path from "path"
import { ArsenalData } from "../src/model"

const stage = process.argv[2]
if (!stage) throw new Error("Stage is required")

const root = path.resolve(process.cwd(), "..", "..", "..")
const PARTS = 8

// read the secret
const ret = await $`bun sst secret list`.cwd(root).text()
const lines = ret.split("\n")
const values = Array.from({ length: PARTS }, (_, i) => {
  const value = lines
    .find((line) => line.startsWith(`ARSENAL_MODELS${i + 1}`))
    ?.split("=")
    .slice(1)
    .join("=")
  if (!value) throw new Error(`ARSENAL_MODELS${i + 1} not found`)
  return value
})

// validate value
ArsenalData.validate(JSON.parse(values.join("")))

// update the secret
for (let i = 0; i < PARTS; i++) {
  await $`bun sst secret set ARSENAL_MODELS${i + 1} --stage ${stage} -- ${values[i]}`
}
