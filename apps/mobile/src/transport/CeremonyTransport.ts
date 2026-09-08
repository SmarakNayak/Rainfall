import { CeremonyMessage, NearbyPeer } from '../ceremony/types';

/**
 * The friendship protocol depends on this interface, never directly on BLE.
 * Android BLE is the first production implementation; tests can use an
 * in-memory transport and iOS can implement the same contract later.
 */
export interface CeremonyTransport {
  discover(onPeer: (peer: NearbyPeer) => void): Promise<() => Promise<void>>;
  connect(peer: NearbyPeer): Promise<void>;
  send(message: CeremonyMessage): Promise<void>;
  onMessage(handler: (message: CeremonyMessage) => void): () => void;
  disconnect(): Promise<void>;
}
