import { z } from 'zod';

export const SkippedLineSchema = z.object({
  line: z.string().optional(),
  reason: z.string().optional(),
});
export type SkippedLine = z.infer<typeof SkippedLineSchema>;

// fragment/skipped come from the jasem backend; optional so older payloads parse.
export const OutboundSubSchema = z.object({
  id: z.number(),
  remark: z.string().optional(),
  url: z.string().optional(),
  enabled: z.boolean().optional(),
  allowPrivate: z.boolean().optional(),
  allowInsecure: z.boolean().optional(),
  userAgent: z.string().optional(),
  prepend: z.boolean().optional(),
  fragment: z.boolean().optional(),
  priority: z.number().optional(),
  tagPrefix: z.string().optional(),
  updateInterval: z.number().optional(),
  lastUpdated: z.number().optional(),
  lastError: z.string().optional(),
  outboundCount: z.number().optional(),
  skipped: z.array(SkippedLineSchema).optional(),
});
export type OutboundSub = z.infer<typeof OutboundSubSchema>;
