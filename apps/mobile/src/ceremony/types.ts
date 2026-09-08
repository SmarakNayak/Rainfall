export type CeremonyStatus =
  | 'idle'
  | 'requesting-permission'
  | 'discovering'
  | 'peer-found'
  | 'verification-ready'
  | 'confirming'
  | 'waiting-for-friend'
  | 'friendship-created'
  | 'unsupported'
  | 'failed';

export type NearbyPeer = {
  address: string;
  name: string;
  signalStrength?: number;
};

export type CeremonyMessage = Uint8Array;
