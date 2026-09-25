export type CampaignStatus = 'draft' | 'active' | 'paused';

export interface Campaign {
  id: string;
  name: string;
  status: CampaignStatus;
  budget: number;
  channel: string;
}

const campaigns: Campaign[] = [
  { id: 'camp-1', name: 'Summer Refresh', status: 'active', budget: 12000, channel: 'Email' },
  { id: 'camp-2', name: 'Back to School', status: 'draft', budget: 8000, channel: 'Social' },
  { id: 'camp-3', name: 'Holiday Push', status: 'paused', budget: 25000, channel: 'Paid Search' },
  { id: 'camp-4', name: 'Loyalty Revival', status: 'active', budget: 5000, channel: 'SMS' },
];

const VALID_STATUSES: CampaignStatus[] = ['draft', 'active', 'paused'];

export function listCampaigns(): Campaign[] {
  return campaigns;
}

export function getCampaign(id: string): Campaign {
  const campaign = campaigns.find((c) => c.id === id);
  if (!campaign) {
    throw new Error(`No campaign with id "${id}"`);
  }
  return campaign;
}

export interface CampaignCreate {
  name: string;
  status?: string;
  budget?: string | number;
  channel?: string;
}

let nextCampaignSeq = campaigns.length + 1;

export function createCampaign(create: CampaignCreate): Campaign {
  if (!create.name || !create.name.trim()) {
    throw new Error('A campaign name is required');
  }
  const status = create.status !== undefined ? (create.status as CampaignStatus) : 'draft';
  if (!VALID_STATUSES.includes(status)) {
    throw new Error(`Invalid status "${create.status}" — must be one of ${VALID_STATUSES.join(', ')}`);
  }
  const budget = create.budget !== undefined ? Number(create.budget) : 0;
  if (!Number.isFinite(budget) || budget < 0) {
    throw new Error(`Invalid budget "${create.budget}" — must be a non-negative number`);
  }
  const campaign: Campaign = {
    id: `camp-${nextCampaignSeq++}`,
    name: create.name.trim(),
    status,
    budget,
    channel: create.channel?.trim() || 'Unassigned',
  };
  campaigns.push(campaign);
  return campaign;
}

export interface CampaignUpdate {
  status?: string;
  budget?: string | number;
}

export function updateCampaign(id: string, update: CampaignUpdate): Campaign {
  const campaign = getCampaign(id);
  if (update.status !== undefined) {
    if (!VALID_STATUSES.includes(update.status as CampaignStatus)) {
      throw new Error(`Invalid status "${update.status}" — must be one of ${VALID_STATUSES.join(', ')}`);
    }
    campaign.status = update.status as CampaignStatus;
  }
  if (update.budget !== undefined) {
    const budget = Number(update.budget);
    if (!Number.isFinite(budget) || budget < 0) {
      throw new Error(`Invalid budget "${update.budget}" — must be a non-negative number`);
    }
    campaign.budget = budget;
  }
  return campaign;
}
