export enum DomainStatus {
  OK = 1,
  Pending,
  ClientHold,
  ServerHold,
  Redemption,
  PendingDelete,
  PendingTransfer,
  PendingUpdate,
  PendingRenewal,
};

export const DomainStatusOK = 1;
export const DomainStatusPending = 2;
export const DomainStatusClientHold = 3;
export const DomainStatusServerHold = 4;
export const DomainStatusRedemption = 5; // w/i 30
export const DomainStatusPendingDelete = 6; // w/i 60
export const DomainStatusPendingTransfer = 7;
export const DomainStatusPendingUpdate = 8;
export const DomainStatusPendingRenewal = 9;

type ValueOf<T> = T[keyof T];
type ArrayElement<ArrayType extends readonly unknown[]> = ArrayType extends readonly (infer ElementType)[] ? ElementType : never;

export const DomainRenewPeriodOptions = [90, 365, 730, 1095];
export type DomainRenewPeriodOptions = [90, 365, 730, 1095];
export type DomainRenewPeriodOptionsType = ArrayElement<DomainRenewPeriodOptions>;

export interface Domain {
  id: string;
  user_id: string;
  domain: string;
  status: DomainStatus;
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
