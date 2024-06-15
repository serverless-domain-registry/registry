export const DomainStatusOK = 1;
export const DomainStatusPending = 2;
export const DomainStatusClientHold = 3;
export const DomainStatusServerHold = 4;
export const DomainStatusRedemption = 5; // w/i 30
export const DomainStatusPendingDelete = 6; // w/i 60
export const DomainStatusPendingTransfer = 7;
export const DomainStatusPendingUpdate = 8;
export const DomainStatusPendingRenewal = 9;

export interface Domain {
  id: string;
  user_id: string;
  domain: string;
  status: typeof DomainStatusOK | typeof DomainStatusPending | typeof DomainStatusClientHold | typeof DomainStatusServerHold | typeof DomainStatusRedemption | typeof DomainStatusPendingDelete | typeof DomainStatusPendingTransfer | typeof DomainStatusPendingUpdate | typeof DomainStatusPendingRenewal; 
  ns_servers: string;
  type: 'free'|'vip';
  created_at: number;
  expires_at: number;
  updated_at: null|number;
  contact?: string;
}

export interface User {
  id: string;
  email: string;
  mfa_secret: string;
  credit: number;
  total_spent: number;
  created_at: number;
  updated_at: null|number;
}
