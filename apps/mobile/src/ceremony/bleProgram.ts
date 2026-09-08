import { Effect } from 'effect';
import { PermissionsAndroid, Platform } from 'react-native';

import RainfallBle from '../../modules/rainfall-ble';

export class BlePermissionError extends Error {
  readonly _tag = 'BlePermissionError';
}

export class BleStartError extends Error {
  readonly _tag = 'BleStartError';
}

export class BleConfirmationError extends Error {
  readonly _tag = 'BleConfirmationError';
}

const requestPermissions = Effect.tryPromise({
  try: async () => {
    if (Platform.OS !== 'android') throw new Error('Android is required');

    const permissions =
      Number(Platform.Version) >= 31
        ? [
            PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
            PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
            PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
          ]
        : [PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION];
    const result = await PermissionsAndroid.requestMultiple(permissions);
    if (permissions.some((permission) => result[permission] !== 'granted')) {
      throw new Error('Nearby devices permission was denied');
    }
  },
  catch: (cause) => new BlePermissionError(String(cause)),
});

const startNativeDiscovery = Effect.tryPromise({
  try: () => RainfallBle.startDiscovery(),
  catch: (cause) => new BleStartError(String(cause)),
});

export const startBleCeremony = requestPermissions.pipe(
  Effect.andThen(startNativeDiscovery),
);

export const stopBleCeremony = Effect.promise(() => RainfallBle.stopDiscovery());

export const connectToBlePeer = (address: string) => Effect.tryPromise({
  try: () => RainfallBle.connectToPeer(address),
  catch: (cause) => new BleStartError(String(cause)),
});

export const confirmBleCeremony = Effect.tryPromise({
  try: () => RainfallBle.confirmCeremony(),
  catch: (cause) => new BleConfirmationError(String(cause)),
});
