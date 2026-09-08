import { StatusBar } from 'expo-status-bar';
import { Effect } from 'effect';
import { useEffect, useState } from 'react';
import {
  Pressable,
  SafeAreaView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import { CeremonyStatus } from './src/ceremony/types';
import {
  confirmBleCeremony,
  connectToBlePeer,
  startBleCeremony,
  stopBleCeremony,
} from './src/ceremony/bleProgram';
import RainfallBle from './modules/rainfall-ble';
import type { NearbyPeer } from './src/ceremony/types';

const statusCopy: Record<CeremonyStatus, string> = {
  idle: 'Friends help each other recover when a device is lost.',
  'requesting-permission': 'Rainfall needs permission to find the phone beside you.',
  discovering: 'Looking for another Rainfall device nearby…',
  'peer-found': 'Another Rainfall device is close. Connecting…',
  'verification-ready': 'Compare this code out loud. It must match on both phones.',
  confirming: 'Sending your confirmation…',
  'waiting-for-friend': 'You confirmed. Waiting for your friend to confirm on their phone.',
  'friendship-created': 'You are now friends. This phone saved their verified identity.',
  unsupported: 'This phone does not support the required Bluetooth mode.',
  failed: 'The Bluetooth ceremony could not start. Check permissions and try again.',
};

export default function App() {
  const [status, setStatus] = useState<CeremonyStatus>('idle');
  const [verificationCode, setVerificationCode] = useState<string>();
  const [friendCount, setFriendCount] = useState(0);
  const [nearbyPeers, setNearbyPeers] = useState<NearbyPeer[]>([]);
  const [profileName, setProfileName] = useState<string | null>(null);
  const [profileDraft, setProfileDraft] = useState('');

  useEffect(() => {
    const stateSubscription = RainfallBle.addListener('onStateChanged', (event) => {
      if (event.state === 'connecting') setStatus('peer-found');
      if (event.state === 'verification-ready') {
        setVerificationCode(event.code);
        setStatus('verification-ready');
      }
      if (event.state === 'waiting-for-friend') setStatus('waiting-for-friend');
      if (event.state === 'friendship-created') {
        setStatus('friendship-created');
        RainfallBle.getFriendCount().then(setFriendCount);
      }
    });
    const peerSubscription = RainfallBle.addListener('onPeerFound', (event) => {
      setNearbyPeers((current) => {
        const peer = { address: event.address, name: event.name, signalStrength: event.rssi };
        const withoutPeer = current.filter(({ address }) => address !== event.address);
        return [...withoutPeer, peer].sort(
          (left, right) => (right.signalStrength ?? -127) - (left.signalStrength ?? -127),
        );
      });
    });
    const errorSubscription = RainfallBle.addListener('onError', () => setStatus('failed'));
    RainfallBle.getFriendCount().then(setFriendCount);
    RainfallBle.getProfileName().then((name) => {
      setProfileName(name);
      setProfileDraft(name);
    });

    return () => {
      stateSubscription.remove();
      peerSubscription.remove();
      errorSubscription.remove();
      Effect.runFork(stopBleCeremony);
    };
  }, []);

  const beginCeremony = () => {
    setVerificationCode(undefined);
    setNearbyPeers([]);
    setStatus('requesting-permission');
    Effect.runPromise(startBleCeremony).then(
      () => setStatus('discovering'),
      () => setStatus('failed'),
    );
  };

  const selectPeer = (peer: NearbyPeer) => {
    setStatus('peer-found');
    Effect.runPromise(connectToBlePeer(peer.address)).catch(() => setStatus('failed'));
  };

  const confirmCeremony = () => {
    setStatus('confirming');
    Effect.runPromise(confirmBleCeremony).catch(() => setStatus('failed'));
  };

  const saveProfile = () => {
    const name = profileDraft.trim();
    if (!name) return;
    Effect.runPromise(Effect.promise(() => RainfallBle.setProfileName(name))).then(
      () => setProfileName(name),
      () => setStatus('failed'),
    );
  };

  return (
    <SafeAreaView style={styles.screen}>
      <StatusBar style="light" />
      <View style={styles.cloudOne} />
      <View style={styles.cloudTwo} />

      <View style={styles.content}>
        <Text style={styles.eyebrow}>RAINFALL</Text>
        {profileName === null ? (
          <Text style={styles.body}>Opening your profile…</Text>
        ) : profileName === '' ? (
          <>
            <Text style={styles.title}>What should people nearby call you?</Text>
            <Text style={styles.body}>
              This profile name is shown to Rainfall users during an in-person ceremony.
            </Text>
            <TextInput
              autoCapitalize="words"
              autoCorrect={false}
              maxLength={40}
              onChangeText={setProfileDraft}
              onSubmitEditing={saveProfile}
              placeholder="Your name"
              placeholderTextColor="#6F8798"
              returnKeyType="done"
              style={styles.nameInput}
              value={profileDraft}
            />
            <Pressable
              accessibilityRole="button"
              disabled={!profileDraft.trim()}
              onPress={saveProfile}
              style={({ pressed }) => [styles.button, pressed && styles.buttonPressed]}
            >
              <Text style={styles.buttonText}>Continue</Text>
            </Pressable>
          </>
        ) : (
          <>
            <Text style={styles.profileName}>Pairing as {profileName}</Text>
            <Text style={styles.title}>Friendship with consequence.</Text>
            <Text style={styles.body}>{statusCopy[status]}</Text>

        {status === 'discovering' && nearbyPeers.length > 0 ? (
          <View accessibilityLabel="Nearby Rainfall devices" style={styles.peerList}>
            {nearbyPeers.map((peer) => (
              <Pressable
                key={peer.address}
                onPress={() => selectPeer(peer)}
                style={({ pressed }) => [styles.peer, pressed && styles.buttonPressed]}
              >
                <View>
                  <Text style={styles.peerName}>{peer.name}</Text>
                  <Text style={styles.peerAddress}>{peer.address}</Text>
                </View>
                <Text style={styles.peerSignal}>{peer.signalStrength} dBm</Text>
              </Pressable>
            ))}
          </View>
        ) : null}

        {verificationCode && !['friendship-created', 'failed'].includes(status) ? (
          <Text accessibilityLabel={`Verification code ${verificationCode}`} style={styles.code}>
            {verificationCode}
          </Text>
        ) : null}

        <Pressable
          accessibilityRole="button"
          disabled={!['idle', 'failed', 'unsupported', 'verification-ready'].includes(status)}
          onPress={status === 'verification-ready' ? confirmCeremony : beginCeremony}
          style={({ pressed }) => [
            styles.button,
            pressed && styles.buttonPressed,
          ]}
        >
          <Text style={styles.buttonText}>
            {status === 'verification-ready'
              ? 'The codes match — confirm'
              : status === 'idle' || status === 'failed' || status === 'unsupported'
              ? 'Add a friend in person'
              : status === 'friendship-created'
                ? 'Friend added'
                : 'Searching nearby'}
          </Text>
        </Pressable>

        <Text style={styles.note}>
          {friendCount} {friendCount === 1 ? 'friend' : 'friends'} on this device · Both people must approve.
        </Text>
          </>
        )}
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: '#07131F',
    overflow: 'hidden',
  },
  content: {
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: 28,
  },
  eyebrow: {
    color: '#72C7FF',
    fontSize: 13,
    fontWeight: '700',
    letterSpacing: 3,
    marginBottom: 18,
  },
  title: {
    color: '#F5FAFF',
    fontSize: 46,
    fontWeight: '700',
    letterSpacing: -1.5,
    lineHeight: 50,
    maxWidth: 330,
  },
  body: {
    color: '#B8CAD8',
    fontSize: 18,
    lineHeight: 27,
    marginBottom: 42,
    marginTop: 22,
    maxWidth: 340,
  },
  button: {
    alignItems: 'center',
    backgroundColor: '#DDF3FF',
    borderRadius: 18,
    paddingHorizontal: 22,
    paddingVertical: 18,
  },
  nameInput: {
    backgroundColor: '#102B40',
    borderColor: '#24506C',
    borderRadius: 16,
    borderWidth: 1,
    color: '#F5FAFF',
    fontSize: 18,
    marginBottom: 16,
    paddingHorizontal: 18,
    paddingVertical: 16,
  },
  profileName: {
    color: '#72C7FF',
    fontSize: 14,
    marginBottom: 12,
  },
  buttonPressed: {
    opacity: 0.8,
    transform: [{ scale: 0.99 }],
  },
  buttonText: {
    color: '#07131F',
    fontSize: 16,
    fontWeight: '700',
  },
  note: {
    color: '#6F8798',
    fontSize: 13,
    lineHeight: 19,
    marginTop: 16,
    textAlign: 'center',
  },
  code: {
    color: '#F5FAFF',
    fontSize: 25,
    fontWeight: '700',
    letterSpacing: 2,
    marginBottom: 30,
    textAlign: 'center',
  },
  peerList: {
    gap: 10,
    marginBottom: 24,
  },
  peer: {
    alignItems: 'center',
    backgroundColor: '#102B40',
    borderColor: '#24506C',
    borderRadius: 16,
    borderWidth: 1,
    flexDirection: 'row',
    justifyContent: 'space-between',
    padding: 16,
  },
  peerName: {
    color: '#F5FAFF',
    fontSize: 17,
    fontWeight: '700',
  },
  peerAddress: {
    color: '#6F8798',
    fontSize: 12,
    marginTop: 4,
  },
  peerSignal: {
    color: '#72C7FF',
    fontSize: 12,
  },
  cloudOne: {
    backgroundColor: '#123752',
    borderRadius: 180,
    height: 280,
    opacity: 0.62,
    position: 'absolute',
    right: -130,
    top: -110,
    width: 360,
  },
  cloudTwo: {
    backgroundColor: '#0E2940',
    borderRadius: 150,
    bottom: -170,
    height: 300,
    left: -120,
    opacity: 0.8,
    position: 'absolute',
    width: 300,
  },
});
