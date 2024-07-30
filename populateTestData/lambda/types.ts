export type CompanyInfo = {
  companyId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  endOfPeriod: Date;
  address: string | null | undefined;
  address2: string | null | undefined;
  city: string | null | undefined;
  state: string | null | undefined;
  zip: string | null | undefined;
  country: string | null | undefined;
  phone: string | null | undefined;
  website: string | null | undefined;
  email: string;
  billingCustomerId: string;
  editGroups: string[];
  readGroups: string[];
  active: boolean;
  __typename: string;
};