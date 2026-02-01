import { Show } from "solid-js"
import { createAsync, useParams } from "@solidjs/router"
import { NewUserSection } from "./new-user-section"
import { UsageSection } from "./usage-section"
import { ModelSection } from "./model-section"
import { ProviderSection } from "./provider-section"
import { GraphSection } from "./graph-section"
import { IconLogo } from "~/component/icon"
import { querySessionInfo } from "../common"

export default function () {
  const params = useParams()
  const userInfo = createAsync(() => querySessionInfo(params.id!))

  return (
    <div data-page="workspace-[id]">
      <section data-component="header-section">
        <IconLogo />
        <p>
          <span>
            Reliable optimized models for coding agents.{" "}
            <a target="_blank" href="/docs/arsenal">
              Learn more
            </a>
            .
          </span>
        </p>
      </section>

      <div data-slot="sections">
        <NewUserSection />
        <Show when={userInfo()?.isAdmin}>
          <GraphSection />
        </Show>
        <ModelSection />
        <Show when={userInfo()?.isAdmin}>
          <ProviderSection />
        </Show>
        <UsageSection />
      </div>
    </div>
  )
}
