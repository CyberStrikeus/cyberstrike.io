import { type TestimonialItem } from "../types/configDataTypes";
import placeholder from "@images/place-for-photo.png";

// Community testimonials - update with real ones as they come in
export const testimonialData: TestimonialItem[] = [
  {
    avatar: placeholder,
    name: "Alex Chen",
    title: "Senior Security Engineer",
    testimonial: `Cyberstrike cut our vulnerability assessment time by 70%. The AI actually understands context and doesn't just throw false positives at you.`,
  },
  {
    avatar: placeholder,
    name: "Sarah Mitchell",
    title: "Penetration Tester",
    testimonial: `Finally, an AI tool that thinks like a pentester. The reconnaissance phase alone saves me hours on every engagement.`,
  },
  {
    avatar: placeholder,
    name: "Marcus Rodriguez",
    title: "Security Consultant",
    testimonial: `The BYOK model is brilliant. I keep my API costs under control and my client data stays private. Win-win.`,
  },
  {
    avatar: placeholder,
    name: "Emily Watson",
    title: "Red Team Lead",
    testimonial: `Love that it's open source. We forked it, added our custom tools, and now have a pentesting agent tailored to our methodology.`,
  },
  {
    avatar: placeholder,
    name: "James Park",
    title: "Bug Bounty Hunter",
    testimonial: `Being able to switch between Claude and GPT-4 mid-session is a game changer. Different models excel at different tasks.`,
  },
  {
    avatar: placeholder,
    name: "Lisa Thompson",
    title: "CISO",
    testimonial: `Self-hosted, air-gapped, running on local models. Perfect for our compliance requirements. And it's completely free.`,
  },
];

export default testimonialData;
