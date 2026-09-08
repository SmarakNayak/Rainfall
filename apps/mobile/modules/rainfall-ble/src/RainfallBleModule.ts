import { NativeModule, requireNativeModule } from 'expo';

import { RainfallBleEvents } from './RainfallBleModule.types';

declare class RainfallBleModule extends NativeModule<RainfallBleEvents> {
  startDiscovery(): Promise<void>;
  stopDiscovery(): Promise<void>;
  connectToPeer(address: string): Promise<void>;
  confirmCeremony(): Promise<void>;
  getFriendCount(): Promise<number>;
  getProfileName(): Promise<string>;
  setProfileName(name: string): Promise<void>;
}

export default requireNativeModule<RainfallBleModule>('RainfallBle');
