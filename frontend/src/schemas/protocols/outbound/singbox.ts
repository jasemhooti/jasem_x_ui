import { z } from 'zod';

// Pseudo-outbound bridged to a sing-box sidecar; `outbound` is a raw sing-box object.
export const SingboxOutboundSettingsSchema = z.object({
  outbound: z.record(z.string(), z.unknown()),
});
export type SingboxOutboundSettings = z.infer<typeof SingboxOutboundSettingsSchema>;
