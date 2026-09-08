export type PeerEvent = {
  address: string;
  name: string;
  rssi: number;
};

export type StateEvent = {
  address?: string;
  code?: string;
  friendId?: string;
  state:
    | 'advertising'
    | 'scanning'
    | 'peer-found'
    | 'connecting'
    | 'verification-ready'
    | 'waiting-for-friend'
    | 'friendship-created'
    | 'stopped';
};

export type ErrorEvent = {
  code: string;
  message: string;
};

export type RainfallBleEvents = {
  onPeerFound: (event: PeerEvent) => void;
  onStateChanged: (event: StateEvent) => void;
  onError: (event: ErrorEvent) => void;
};
