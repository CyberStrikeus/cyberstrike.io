import { type FaqItem } from "../types/configDataTypes";

export const faqData: FaqItem[] = [
  {
    question: "What is Cyberstrike?",
    answer: `Cyberstrike is an autonomous AI-powered penetration testing agent. It combines multiple AI models
    (Claude, GPT, Gemini) with specialized security tools to perform assessments, identify vulnerabilities,
    and generate detailed reports - all with minimal human intervention. It's 100% open source under the AGPL-3.0 license.`,
  },
  {
    question: "How does the BYOK (Bring Your Own Key) model work?",
    answer: `With BYOK, you use your own API keys from AI providers like Anthropic, OpenAI, or Google.
    This means you have full control over your AI costs, usage limits, and data privacy.
    We never store or have access to your conversations with the AI models.`,
  },
  {
    question: "Is Cyberstrike safe to use on production systems?",
    answer: `Cyberstrike is designed for authorized security testing only. It includes built-in safety
    mechanisms and requires explicit confirmation before performing any potentially destructive actions.
    Always ensure you have proper authorization before testing any system.`,
  },
  {
    question: "What AI models are supported?",
    answer: `Cyberstrike supports Claude (Anthropic), GPT-4 (OpenAI), Gemini (Google), and other major
    AI providers. You can also use local models like Ollama for air-gapped environments.
    Switch between models based on your needs and preferences.`,
  },
  {
    question: "Can I self-host Cyberstrike?",
    answer: `Yes! Cyberstrike is fully self-hostable. You can run it on your own infrastructure,
    use local AI models with Ollama, and keep all data on-premise. Perfect for organizations
    with strict security requirements or air-gapped environments.`,
  },
  {
    question: "Is Cyberstrike free?",
    answer: `Cyberstrike is open source under the AGPL-3.0 license. For personal use, research, and education - it's completely free.
    For commercial use where you don't want to open-source your modifications, we offer a commercial license.
    Contact license@cyberstrike.io for enterprise licensing options.`,
  },
  {
    question: "How can I contribute?",
    answer: `We welcome contributions! Check out our GitHub repository to report issues, submit pull requests,
    or join discussions. Whether it's code, documentation, or security tool integrations - all contributions
    help make Cyberstrike better for the security community.`,
  },
];

export default faqData;
