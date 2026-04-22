/**
 * StalkerwareDetector — Detect surveillance software, AirTag trackers,
 * and digital monitoring on devices. Privacy-first, on-device only.
 */

import { z } from 'zod';

export const DeviceScanResultSchema = z.object({
  scanId: z.string().uuid(), scannedAt: z.string().datetime(),
  deviceType: z.enum(['android', 'ios', 'windows', 'mac']),
  threatLevel: z.enum(['clear', 'suspicious', 'stalkerware_detected', 'multiple_threats']),
  findings: z.array(z.object({
    type: z.enum(['stalkerware_app', 'hidden_app', 'suspicious_permission', 'unknown_device_admin', 'airtag_tracker', 'bluetooth_tracker', 'location_sharing', 'keylogger', 'screen_recorder', 'call_recorder', 'sms_forwarder']),
    severity: z.enum(['critical', 'high', 'medium', 'info']),
    name: z.string(), description: z.string(),
    removalSafe: z.boolean(),
    removalWarning: z.string().optional(),
    removalSteps: z.array(z.string()),
  })),
  permissionAudit: z.object({
    locationAccess: z.array(z.string()), microphoneAccess: z.array(z.string()),
    cameraAccess: z.array(z.string()), smsAccess: z.array(z.string()),
    callLogAccess: z.array(z.string()), contactsAccess: z.array(z.string()),
  }),
  networkAudit: z.object({ suspiciousConnections: z.array(z.object({ destination: z.string(), frequency: z.string(), dataVolume: z.string() })) }).optional(),
  safetyWarning: z.string().optional(),
});

export const DigitalSafetyChecklistSchema = z.object({
  assessedAt: z.string().datetime(),
  items: z.array(z.object({
    category: z.enum(['device_security', 'account_security', 'location_privacy', 'communication_privacy', 'social_media', 'financial_accounts', 'physical_trackers']),
    item: z.string(), status: z.enum(['safe', 'at_risk', 'compromised', 'unchecked']),
    action: z.string(), priority: z.enum(['critical', 'high', 'medium', 'low']),
  })),
  overallScore: z.number().min(0).max(100),
});

export type DeviceScanResult = z.infer<typeof DeviceScanResultSchema>;
export type DigitalSafetyChecklist = z.infer<typeof DigitalSafetyChecklistSchema>;

const KNOWN_STALKERWARE = [
  'mSpy', 'FlexiSPY', 'Cocospy', 'Spyic', 'XNSPY', 'Hoverwatch', 'iKeyMonitor', 'SpyBubble',
  'Highster Mobile', 'pcTattletale', 'TheTruthSpy', 'KidsGuard Pro', 'SpyHuman', 'MobileTracker',
  'Cerberus', 'Life360', 'FamilyLink', 'mLite', 'WebWatcher',
];

export function checkForKnownStalkerware(installedApps: string[]): DeviceScanResult['findings'] {
  const findings: DeviceScanResult['findings'] = [];
  for (const app of installedApps) {
    const match = KNOWN_STALKERWARE.find(s => app.toLowerCase().includes(s.toLowerCase()));
    if (match) {
      findings.push({
        type: 'stalkerware_app', severity: 'critical', name: app,
        description: `${match} is known stalkerware that can monitor calls, texts, location, and more`,
        removalSafe: false,
        removalWarning: 'WARNING: Removing stalkerware may alert the person who installed it. Create a safety plan BEFORE removing. Consider getting a new phone instead.',
        removalSteps: ['Document the finding (screenshot)', 'DO NOT remove yet — create safety plan first', 'Contact DV hotline: 1-800-799-7233', 'Consider new device from safe location', 'If removing: factory reset is most thorough'],
      });
    }
  }
  return findings;
}

export function auditPermissions(appPermissions: Record<string, string[]>): DeviceScanResult['permissionAudit'] {
  const audit: DeviceScanResult['permissionAudit'] = {
    locationAccess: [], microphoneAccess: [], cameraAccess: [],
    smsAccess: [], callLogAccess: [], contactsAccess: [],
  };

  for (const [app, perms] of Object.entries(appPermissions)) {
    if (perms.includes('location') || perms.includes('ACCESS_FINE_LOCATION')) audit.locationAccess.push(app);
    if (perms.includes('microphone') || perms.includes('RECORD_AUDIO')) audit.microphoneAccess.push(app);
    if (perms.includes('camera') || perms.includes('CAMERA')) audit.cameraAccess.push(app);
    if (perms.includes('sms') || perms.includes('READ_SMS')) audit.smsAccess.push(app);
    if (perms.includes('call_log') || perms.includes('READ_CALL_LOG')) audit.callLogAccess.push(app);
    if (perms.includes('contacts') || perms.includes('READ_CONTACTS')) audit.contactsAccess.push(app);
  }

  return audit;
}

export function generateDigitalSafetyChecklist(): DigitalSafetyChecklist {
  return {
    assessedAt: new Date().toISOString(),
    overallScore: 0,
    items: [
      { category: 'device_security', item: 'Scan device for stalkerware', status: 'unchecked', action: 'Run stalkerware detection scan', priority: 'critical' },
      { category: 'device_security', item: 'Change device passcode', status: 'unchecked', action: 'Set new PIN/password unknown to abuser', priority: 'critical' },
      { category: 'device_security', item: 'Disable biometric unlock if abuser has access', status: 'unchecked', action: 'Remove fingerprint/face data, use PIN only', priority: 'high' },
      { category: 'account_security', item: 'Change email password', status: 'unchecked', action: 'Create new password from safe device', priority: 'critical' },
      { category: 'account_security', item: 'Enable 2FA on all accounts', status: 'unchecked', action: 'Use authenticator app (not SMS)', priority: 'critical' },
      { category: 'account_security', item: 'Check account recovery options', status: 'unchecked', action: 'Remove abuser phone/email from recovery', priority: 'high' },
      { category: 'location_privacy', item: 'Disable location sharing', status: 'unchecked', action: 'Turn off Find My, Google location sharing, Life360', priority: 'critical' },
      { category: 'location_privacy', item: 'Scan for physical trackers (AirTag, Tile)', status: 'unchecked', action: 'Check car, bags, jacket pockets, children\'s items', priority: 'critical' },
      { category: 'communication_privacy', item: 'Check call/text forwarding', status: 'unchecked', action: 'Dial *#21# to check forwarding status', priority: 'high' },
      { category: 'social_media', item: 'Review social media privacy settings', status: 'unchecked', action: 'Set to private, remove abuser from friends/followers', priority: 'medium' },
      { category: 'social_media', item: 'Disable location tagging on posts', status: 'unchecked', action: 'Turn off geotagging in all social media apps', priority: 'high' },
      { category: 'financial_accounts', item: 'Open separate bank account', status: 'unchecked', action: 'New account at different bank with paperless statements', priority: 'high' },
      { category: 'physical_trackers', item: 'Check vehicle for GPS trackers', status: 'unchecked', action: 'Inspect under vehicle, wheel wells, OBD port, trunk', priority: 'high' },
    ],
  };
}
