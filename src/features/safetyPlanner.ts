/**
 * SafetyPlanner — On-device safety planning and danger assessment
 * for domestic violence survivors. ZERO cloud dependency.
 */

import { z } from 'zod';

export const DangerAssessmentSchema = z.object({
  id: z.string().uuid(), assessedAt: z.string().datetime(),
  // Campbell Danger Assessment validated questions
  responses: z.object({
    physicalViolenceIncreased: z.boolean(), weaponAvailable: z.boolean(),
    strangulationAttempt: z.boolean(), forcedSexual: z.boolean(),
    substanceAbuse: z.boolean(), threatenedKill: z.boolean(),
    employedStatus: z.boolean(), stalking: z.boolean(),
    leftAfterLivingTogether: z.boolean(), controlsMostActivities: z.boolean(),
    violentDuringPregnancy: z.boolean(), suicideThreat: z.boolean(),
    threatenedChildren: z.boolean(), believesCapableOfKilling: z.boolean(),
    violenceTowardOthers: z.boolean(), childNotBiological: z.boolean(),
    petAbuse: z.boolean(), forcedFinancialDependence: z.boolean(),
    spiedOnTracked: z.boolean(), destroyedProperty: z.boolean(),
  }),
  score: z.number().int().min(0).max(20),
  riskLevel: z.enum(['variable', 'increased', 'severe', 'extreme']),
  keyIndicators: z.array(z.string()),
});

export const SafetyPlanSchema = z.object({
  id: z.string().uuid(), createdAt: z.string().datetime(), onDevice: z.literal(true),
  warningSignsPersonal: z.array(z.string()),
  safePlaces: z.array(z.object({ name: z.string(), address: z.string(), phone: z.string().optional(), hoursOfAccess: z.string() })),
  emergencyContacts: z.array(z.object({ name: z.string(), phone: z.string(), codeWord: z.string().optional() })),
  goBag: z.object({
    documents: z.array(z.string()), essentials: z.array(z.string()),
    location: z.string(), accessible: z.boolean(),
  }),
  financialSafety: z.object({
    separateAccount: z.boolean(), hiddenCash: z.boolean(), hiddenCashAmount: z.number().optional(),
    creditInOwnName: z.boolean(),
  }),
  digitalSafety: z.object({
    passwordsChanged: z.boolean(), twoFactorEnabled: z.boolean(),
    locationSharingDisabled: z.boolean(), separateEmail: z.boolean(),
    deviceSecured: z.boolean(), socialMediaPrivacy: z.boolean(),
    stalkerwareChecked: z.boolean(),
  }),
  legalProtections: z.object({
    protectionOrder: z.boolean(), protectionOrderExpiry: z.string().optional(),
    custodyArrangement: z.string().optional(), lawyerContact: z.string().optional(),
  }),
  childrenPlan: z.object({
    hasChildren: z.boolean(), schoolNotified: z.boolean(),
    childCareBackup: z.string().optional(), custodyDocsCopied: z.boolean(),
  }).optional(),
  exitRoute: z.object({
    primaryRoute: z.string(), alternateRoute: z.string(),
    timeOfDay: z.string(), vehicleAccess: z.boolean(),
    prearrangedTransport: z.boolean(),
  }),
});

export const EvidenceEntrySchema = z.object({
  id: z.string().uuid(), recordedAt: z.string().datetime(),
  type: z.enum(['text', 'photo', 'audio', 'screenshot', 'medical_record', 'police_report']),
  description: z.string(),
  encryptedHash: z.string(),
  chainOfCustody: z.array(z.object({ action: z.string(), timestamp: z.string(), actor: z.string() })),
  metadata: z.object({ gpsCoordinates: z.object({ lat: z.number(), lon: z.number() }).optional(), fileSize: z.number().int().optional() }).optional(),
});

export type DangerAssessment = z.infer<typeof DangerAssessmentSchema>;
export type SafetyPlan = z.infer<typeof SafetyPlanSchema>;
export type EvidenceEntry = z.infer<typeof EvidenceEntrySchema>;

const HIGH_LETHALITY_FACTORS = ['strangulationAttempt', 'threatenedKill', 'weaponAvailable', 'believesCapableOfKilling', 'stalking', 'forcedSexual'] as const;

export function assessDanger(responses: DangerAssessmentSchema['shape']['responses']['_output']): DangerAssessment {
  const score = Object.values(responses).filter(Boolean).length;
  const keyIndicators: string[] = [];

  if (responses.strangulationAttempt) keyIndicators.push('CRITICAL: Strangulation is the single strongest predictor of homicide');
  if (responses.threatenedKill) keyIndicators.push('Death threats present');
  if (responses.weaponAvailable) keyIndicators.push('Weapon accessible');
  if (responses.stalking) keyIndicators.push('Stalking behavior');
  if (responses.physicalViolenceIncreased) keyIndicators.push('Violence escalating');
  if (responses.forcedFinancialDependence) keyIndicators.push('Financial control/coercion');
  if (responses.spiedOnTracked) keyIndicators.push('Surveillance/tracking — check for stalkerware');

  const highLethalityCount = HIGH_LETHALITY_FACTORS.filter(f => responses[f]).length;
  const riskLevel = highLethalityCount >= 3 || score >= 16 ? 'extreme' as const
    : highLethalityCount >= 2 || score >= 12 ? 'severe' as const
    : score >= 8 ? 'increased' as const : 'variable' as const;

  return { id: crypto.randomUUID(), assessedAt: new Date().toISOString(), responses, score, riskLevel, keyIndicators };
}

export function generateSafetyPlan(dangerLevel: DangerAssessment['riskLevel']): Partial<SafetyPlan> {
  const goBagDocuments = ['ID/passport', 'Birth certificates (self + children)', 'Protection order copies', 'Insurance cards', 'Medication list', 'Bank account info', 'Lease/mortgage documents', 'Phone charger'];
  const goBagEssentials = ['3 days clothing', 'Cash', 'Keys (house, car, work)', 'Phone', 'Medications', 'Children\'s essentials', 'Comfort item for children'];

  return {
    id: crypto.randomUUID(), createdAt: new Date().toISOString(), onDevice: true,
    warningSignsPersonal: ['Note your abuser\'s specific warning signs here'],
    safePlaces: [], emergencyContacts: [],
    goBag: { documents: goBagDocuments, essentials: goBagEssentials, location: 'Set a safe location', accessible: false },
    financialSafety: { separateAccount: false, hiddenCash: false, creditInOwnName: false },
    digitalSafety: { passwordsChanged: false, twoFactorEnabled: false, locationSharingDisabled: false, separateEmail: false, deviceSecured: false, socialMediaPrivacy: false, stalkerwareChecked: false },
    legalProtections: { protectionOrder: false },
    exitRoute: { primaryRoute: 'Plan your primary escape route', alternateRoute: 'Plan a backup route', timeOfDay: 'Safest time to leave', vehicleAccess: false, prearrangedTransport: false },
  };
}
