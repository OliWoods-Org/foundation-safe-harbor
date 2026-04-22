/**
 * ResourceConnector — Connect DV survivors to shelters, legal aid,
 * financial assistance, and counseling by location.
 */

import { z } from 'zod';

export const DVResourceSchema = z.object({
  id: z.string(), name: z.string(),
  type: z.enum(['shelter', 'legal_aid', 'counseling', 'financial', 'hotline', 'support_group', 'medical', 'housing', 'childcare', 'job_training']),
  location: z.object({ city: z.string(), state: z.string(), latitude: z.number().optional(), longitude: z.number().optional() }).optional(),
  phone: z.string().optional(), website: z.string().url().optional(),
  hours: z.string(), languages: z.array(z.string()),
  servesChildren: z.boolean(), servesPets: z.boolean(),
  servesLGBTQ: z.boolean(), servesMen: z.boolean(),
  acceptsMedicaid: z.boolean().optional(),
  confidential: z.boolean(),
  description: z.string(),
});

export const ResourceMatchSchema = z.object({
  matchedAt: z.string().datetime(),
  resources: z.array(z.object({ resource: DVResourceSchema, distanceMiles: z.number().optional(), relevanceScore: z.number().min(0).max(100), whyRecommended: z.string() })),
  nationalHotlines: z.array(z.object({ name: z.string(), phone: z.string(), text: z.string().optional(), chat: z.string().url().optional(), available: z.string() })),
});

export type DVResource = z.infer<typeof DVResourceSchema>;
export type ResourceMatch = z.infer<typeof ResourceMatchSchema>;

const NATIONAL_HOTLINES = [
  { name: 'National DV Hotline', phone: '1-800-799-7233', text: 'Text START to 88788', chat: 'https://www.thehotline.org/get-help/', available: '24/7' },
  { name: 'National Sexual Assault Hotline', phone: '1-800-656-4673', available: '24/7' },
  { name: 'StrongHearts Native Helpline', phone: '1-844-762-8483', available: '24/7' },
  { name: 'Love is Respect (youth)', phone: '1-866-331-9474', text: 'Text LOVEIS to 22522', available: '24/7' },
  { name: 'Trans Lifeline', phone: '1-877-565-8860', available: '24/7' },
  { name: 'National Center for Victims of Crime', phone: '1-855-484-2846', available: 'Mon-Fri 9-5 ET' },
];

export function matchResources(
  needs: Array<DVResource['type']>,
  hasChildren: boolean,
  hasPets: boolean,
  language: string,
  resources: DVResource[]
): ResourceMatch {
  const matched = resources
    .filter(r => needs.includes(r.type))
    .filter(r => !hasChildren || r.servesChildren || r.type !== 'shelter')
    .filter(r => !hasPets || r.servesPets || r.type !== 'shelter')
    .filter(r => r.languages.includes(language) || r.languages.includes('en'))
    .map(r => {
      let score = 50;
      if (r.languages.includes(language)) score += 15;
      if (hasChildren && r.servesChildren) score += 10;
      if (hasPets && r.servesPets) score += 10;
      if (r.confidential) score += 10;

      const whyRecommended = [
        `${r.type.replace('_', ' ')} service`,
        r.confidential ? 'confidential' : '',
        hasChildren && r.servesChildren ? 'accepts children' : '',
        hasPets && r.servesPets ? 'pet-friendly' : '',
      ].filter(Boolean).join(', ');

      return { resource: r, relevanceScore: Math.min(100, score), whyRecommended };
    })
    .sort((a, b) => b.relevanceScore - a.relevanceScore);

  return { matchedAt: new Date().toISOString(), resources: matched, nationalHotlines: NATIONAL_HOTLINES };
}
