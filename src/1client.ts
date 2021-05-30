/*
Copyright 2015-2021 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * This is an internal module. See {@link MatrixClient} for the public class.
 * @module client
 */

import { EventEmitter } from "events";
import { SyncApi } from "./sync";
import { EventStatus, MatrixEvent } from "./models/event";
import { StubStore } from "./store/stub";
import { createNewMatrixCall, MatrixCall } from "./webrtc/call";
import { CallEventHandler } from './webrtc/callEventHandler';
import * as utils from './utils';
import { Group } from "./models/group";
import { PREFIX_MEDIA_R0, PREFIX_UNSTABLE, retryNetworkOperation, } from "./http-api";
import * as olmlib from "./crypto/olmlib";
import { decodeBase64, encodeBase64 } from "./crypto/olmlib";
import { ReEmitter } from './ReEmitter';
import { RoomList } from './crypto/RoomList';
import { logger } from './logger';
import { Crypto, DeviceInfo, fixBackupKey, isCryptoAvailable } from './crypto';
import { decodeRecoveryKey } from './crypto/recoverykey';
import { keyFromAuthData } from './crypto/key_passphrase';
import { PushProcessor } from "./pushprocessor";
import { User } from "./models/user";
import { DEHYDRATION_ALGORITHM, IDehydratedDevice, IDehydratedDeviceKeyInfo } from "./crypto/dehydration";
import {
    IKeyBackupPrepareOpts,
    IKeyBackupRestoreOpts,
    IKeyBackupRestoreResult,
    IKeyBackupRoomSessions,
    IKeyBackupSession,
    IKeyBackupTrustInfo,
    IKeyBackupVersion
} from "./crypto/keybackup";
import { PkDecryption } from "olm";
import { IIdentityServerProvider } from "./@types/IIdentityServerProvider";
import type Request from "request";
import { MatrixScheduler } from "./scheduler";
import { ICryptoCallbacks, IDeviceTrustLevel, ISecretStorageKeyInfo } from "./matrix";
import { MemoryCryptoStore } from "./crypto/store/memory-crypto-store";
import { LocalStorageCryptoStore } from "./crypto/store/localStorage-crypto-store";
import { IndexedDBCryptoStore } from "./crypto/store/indexeddb-crypto-store";
import { MemoryStore } from "./store/memory";
import { LocalIndexedDBStoreBackend } from "./store/indexeddb-local-backend";
import { RemoteIndexedDBStoreBackend } from "./store/indexeddb-remote-backend";
import { SyncState } from "./sync.api";
import { EventTimelineSet } from "./models/event-timeline-set";
import { VerificationRequest } from "./crypto/verification/request/VerificationRequest";
import { Base as Verification } from "./crypto/verification/Base";
import * as ContentHelpers from "./content-helpers";
import {
    CrossSigningKey,
    IAddSecretStorageKeyOpts,
    ICreateSecretStorageOpts,
    IEncryptedEventInfo,
    IImportRoomKeysOpts,
    IRecoveryKey,
    ISecretStorageKey
} from "./crypto/api";
import { CrossSigningInfo, UserTrustLevel } from "./crypto/CrossSigning";
import { Room } from "./models/Room";
import { IJoinRoomOpts, IRedactOpts, ISendEventResponse } from "./@types/requests";
import { EventType } from "./@types/event";
import { IImageInfo } from "./@types/partials";

export type Store = StubStore | MemoryStore | LocalIndexedDBStoreBackend | RemoteIndexedDBStoreBackend;

export type CryptoStore = MemoryCryptoStore | LocalStorageCryptoStore | IndexedDBCryptoStore;

export type Callback = (err: Error | any | null, data?: any) => void;

const SCROLLBACK_DELAY_MS = 3000;
export const CRYPTO_ENABLED: boolean = isCryptoAvailable();
const CAPABILITIES_CACHE_MS = 21600000; // 6 hours - an arbitrary value
const TURN_CHECK_INTERVAL = 10 * 60 * 1000; // poll for turn credentials every 10 minutes

function keysFromRecoverySession(sessions: IKeyBackupRoomSessions, decryptionKey: PkDecryption, roomId: string) {
    const keys = [];
    for (const [sessionId, sessionData] of Object.entries(sessions)) {
        try {
            const decrypted = keyFromRecoverySession(sessionData, decryptionKey);
            decrypted.session_id = sessionId;
            decrypted.room_id = roomId;
            keys.push(decrypted);
        } catch (e) {
            logger.log("Failed to decrypt megolm session from backup", e);
        }
    }
    return keys;
}

function keyFromRecoverySession(session: IKeyBackupSession, decryptionKey: PkDecryption) {
    return JSON.parse(decryptionKey.decrypt(
        session.session_data.ephemeral,
        session.session_data.mac,
        session.session_data.ciphertext,
    ));
}

interface IOlmDevice {
    pickledAccount: string;
    sessions: Array<Record<string, any>>;
    pickleKey: string;
}

interface IExportedDevice {
    olmDevice: IOlmDevice;
    userId: string;
    deviceId: string;
}

export interface ICreateClientOpts {
    baseUrl: string;

    idBaseUrl?: string;

    /**
     * The data store used for sync data from the homeserver. If not specified,
     * this client will not store any HTTP responses. The `createClient` helper
     * will create a default store if needed.
     */
    store?: Store;

    /**
     * A store to be used for end-to-end crypto session data. If not specified,
     * end-to-end crypto will be disabled. The `createClient` helper will create
     * a default store if needed.
     */
    cryptoStore?: CryptoStore;

    /**
     * The scheduler to use. If not
     * specified, this client will not retry requests on failure. This client
     * will supply its own processing function to
     * {@link module:scheduler~MatrixScheduler#setProcessFunction}.
     */
    scheduler?: MatrixScheduler;

    /**
     * The function to invoke for HTTP
     * requests. The value of this property is typically <code>require("request")
     * </code> as it returns a function which meets the required interface. See
     * {@link requestFunction} for more information.
     */
    request?: Request;

    userId?: string;

    /**
     * A unique identifier for this device; used for tracking things like crypto
     * keys and access tokens. If not specified, end-to-end encryption will be
     * disabled.
     */
    deviceId?: string;

    accessToken?: string;

    /**
     * Identity server provider to retrieve the user's access token when accessing
     * the identity server. See also https://github.com/vector-im/element-web/issues/10615
     * which seeks to replace the previous approach of manual access tokens params
     * with this callback throughout the SDK.
     */
    identityServer?: IIdentityServerProvider;

    /**
     * The default maximum amount of
     * time to wait before timing out HTTP requests. If not specified, there is no timeout.
     */
    localTimeoutMs?: number;

    /**
     * Set to true to use
     * Authorization header instead of query param to send the access token to the server.
     *
     * Default false.
     */
    useAuthorizationHeader?: boolean;

    /**
     * Set to true to enable
     * improved timeline support ({@link module:client~MatrixClient#getEventTimeline getEventTimeline}). It is
     * disabled by default for compatibility with older clients - in particular to
     * maintain support for back-paginating the live timeline after a '/sync'
     * result with a gap.
     */
    timelineSupport?: boolean;

    /**
     * Extra query parameters to append
     * to all requests with this client. Useful for application services which require
     * <code>?user_id=</code>.
     */
    queryParams?: Record<string, unknown>;

    /**
     * Device data exported with
     * "exportDevice" method that must be imported to recreate this device.
     * Should only be useful for devices with end-to-end crypto enabled.
     * If provided, deviceId and userId should **NOT** be provided at the top
     * level (they are present in the exported data).
     */
    deviceToImport?: IExportedDevice;

    /**
     * Key used to pickle olm objects or other sensitive data.
     */
    pickleKey?: string;

    /**
     * A store to be used for end-to-end crypto session data. Most data has been
     * migrated out of here to `cryptoStore` instead. If not specified,
     * end-to-end crypto will be disabled. The `createClient` helper
     * _will not_ create this store at the moment.
     */
    sessionStore?: any;

    /**
     * Set to true to enable client-side aggregation of event relations
     * via `EventTimelineSet#getRelationsForEvent`.
     * This feature is currently unstable and the API may change without notice.
     */
    unstableClientRelationAggregation?: boolean;

    verificationMethods?: Array<any>;

    /**
     * Whether relaying calls through a TURN server should be forced. Default false.
     */
    forceTURN?: boolean;

    /**
     * Up to this many ICE candidates will be gathered when an incoming call arrives.
     * Gathering does not send data to the caller, but will communicate with the configured TURN
     * server. Default 0.
     */
    iceCandidatePoolSize?: number;

    /**
     * True to advertise support for call transfers to other parties on Matrix calls. Default false.
     */
    supportsCallTransfer?: boolean;

    /**
     * Whether to allow a fallback ICE server should be used for negotiating a
     * WebRTC connection if the homeserver doesn't provide any servers. Defaults to false.
     */
    fallbackICEServerAllowed?: boolean;

    cryptoCallbacks?: ICryptoCallbacks;
}

export interface IMatrixClientCreateOpts extends ICreateClientOpts {
    /**
     * Whether to allow sending messages to encrypted rooms when encryption
     * is not available internally within this SDK. This is useful if you are using an external
     * E2E proxy, for example. Defaults to false.
     */
    usingExternalCrypto?: boolean;
}
/**
 * Represents a Matrix Client. Only directly construct this if you want to use
 * custom modules. Normally, {@link createClient} should be used
 * as it specifies 'sensible' defaults for these modules.
 */
export class MatrixClient extends EventEmitter {
    public static readonly RESTORE_BACKUP_ERROR_BAD_KEY = 'RESTORE_BACKUP_ERROR_BAD_KEY';

    public reEmitter = new ReEmitter(this);
    public olmVersion: number = null; // populated after initCrypto
    public usingExternalCrypto = false;
    public store: Store;
    public deviceId?: string;
    public credentials: {userId?: string};
    public pickleKey: string;
    public scheduler: MatrixScheduler;
    public clientRunning = false;
    public timelineSupport = false;
    public urlPreviewCache: {[key: string]: Promise<unknown>} = {}; // TODO: @@TR
    public unstableClientRelationAggregation = false;

    private canSupportVoip = false;
    private callEventHandler: CallEventHandler;
    private syncingRetry = null; // TODO: @@TR
    private peekSync = null; // TODO: @@TR
    private isGuestAccount = false;
    private ongoingScrollbacks = {}; // TODO: @@TR
    private notifTimelineSet: EventTimelineSet = null;
    private crypto: Crypto;
    private cryptoStore: CryptoStore;
    private sessionStore: any; // TODO: @@TR
    private verificationMethods: string[];
    private cryptoCallbacks: ICryptoCallbacks;
    private forceTURN = false;
    private iceCandidatePoolSize = 0;
    private supportsCallTransfer = false;
    private fallbackICEServerAllowed = false;
    private roomList: RoomList;
    private syncApi: SyncApi;

    // The pushprocessor caches useful things, so keep one and re-use it
    private pushProcessor = new PushProcessor(this);

    // Promise to a response of the server's /versions response
    // TODO: This should expire: https://github.com/matrix-org/matrix-js-sdk/issues/1020
    private serverVersionsPromise: Promise<any>;

    private cachedCapabilities: {
        capabilities: Record<string, any>;
        expiration: number;
    };
    private clientWellKnown: any; // TODO: @@TR
    private clientWellKnownPromise: Promise<any>; // TODO: @@TR
    private turnServers: any[] = []; // TODO: @@TR
    private turnServersExpiry = 0;
    private checkTurnServersIntervalID: number;
    private exportedOlmDeviceToImport: IOlmDevice;

    constructor(opts: IMatrixClientCreateOpts) {
        super();

        opts.baseUrl = utils.ensureNoTrailingSlash(opts.baseUrl);
        opts.idBaseUrl = utils.ensureNoTrailingSlash(opts.idBaseUrl);

        this.usingExternalCrypto = opts.usingExternalCrypto;
        this.store = opts.store || new StubStore();
        this.deviceId = opts.deviceId || null;

        const userId = opts.userId || null;
        this.credentials = {userId};

        if (opts.deviceToImport) {
            if (this.deviceId) {
                logger.warn(
                    'not importing device because device ID is provided to ' +
                    'constructor independently of exported data',
                );
            } else if (this.credentials.userId) {
                logger.warn(
                    'not importing device because user ID is provided to ' +
                    'constructor independently of exported data',
                );
            } else if (!opts.deviceToImport.deviceId) {
                logger.warn('not importing device because no device ID in exported data');
            } else {
                this.deviceId = opts.deviceToImport.deviceId;
                this.credentials.userId = opts.deviceToImport.userId;
                // will be used during async initialization of the crypto
                this.exportedOlmDeviceToImport = opts.deviceToImport.olmDevice;
            }
        } else if (opts.pickleKey) {
            this.pickleKey = opts.pickleKey;
        }

        this.scheduler = opts.scheduler;
        if (this.scheduler) {
            this.scheduler.setProcessFunction(async (eventToSend) => {
                const room = this.getRoom(eventToSend.getRoomId());
                if (eventToSend.status !== EventStatus.SENDING) {
                    this.updatePendingEventStatus(room, eventToSend, EventStatus.SENDING);
                }
                const res = await sendEventHttpRequest(this, eventToSend);
                if (room) {
                    // ensure we update pending event before the next scheduler run so that any listeners to event id
                    // updates on the synchronous event emitter get a chance to run first.
                    room.updatePendingEvent(eventToSend, EventStatus.SENT, res.event_id);
                }
                return res;
            });
        }

        // try constructing a MatrixCall to see if we are running in an environment
        // which has WebRTC. If we are, listen for and handle m.call.* events.
        const call = createNewMatrixCall(this, undefined, undefined);
        if (call) {
            this.callEventHandler = new CallEventHandler(this);
            this.canSupportVoip = true;
            // Start listening for calls after the initial sync is done
            // We do not need to backfill the call event buffer
            // with encrypted events that might never get decrypted
            this.on("sync", () => this.startCallEventHandler());
        }

        this.timelineSupport = Boolean(opts.timelineSupport);
        this.unstableClientRelationAggregation = !!opts.unstableClientRelationAggregation;

        this.cryptoStore = opts.cryptoStore;
        this.sessionStore = opts.sessionStore;
        this.verificationMethods = opts.verificationMethods;
        this.cryptoCallbacks = opts.cryptoCallbacks || {};

        this.forceTURN = opts.forceTURN || false;
        this.iceCandidatePoolSize = opts.iceCandidatePoolSize === undefined ? 0 : opts.iceCandidatePoolSize;
        this.supportsCallTransfer = opts.supportsCallTransfer || false;
        this.fallbackICEServerAllowed = opts.fallbackICEServerAllowed || false;

        // List of which rooms have encryption enabled: separate from crypto because
        // we still want to know which rooms are encrypted even if crypto is disabled:
        // we don't want to start sending unencrypted events to them.
        this.roomList = new RoomList(this.cryptoStore);

        // The SDK doesn't really provide a clean way for events to recalculate the push
        // actions for themselves, so we have to kinda help them out when they are encrypted.
        // We do this so that push rules are correctly executed on events in their decrypted
        // state, such as highlights when the user's name is mentioned.
        this.on("Event.decrypted", (event) => {
            const oldActions = event.getPushActions();
            const actions = this.pushProcessor.actionsForEvent(event);
            event.setPushActions(actions); // Might as well while we're here

            const room = this.getRoom(event.getRoomId());
            if (!room) return;

            const currentCount = room.getUnreadNotificationCount("highlight");

            // Ensure the unread counts are kept up to date if the event is encrypted
            // We also want to make sure that the notification count goes up if we already
            // have encrypted events to avoid other code from resetting 'highlight' to zero.
            const oldHighlight = oldActions && oldActions.tweaks
                ? !!oldActions.tweaks.highlight : false;
            const newHighlight = actions && actions.tweaks
                ? !!actions.tweaks.highlight : false;
            if (oldHighlight !== newHighlight || currentCount > 0) {
                // TODO: Handle mentions received while the client is offline
                // See also https://github.com/vector-im/element-web/issues/9069
                if (!room.hasUserReadEvent(this.getUserId(), event.getId())) {
                    let newCount = currentCount;
                    if (newHighlight && !oldHighlight) newCount++;
                    if (!newHighlight && oldHighlight) newCount--;
                    room.setUnreadNotificationCount("highlight", newCount);

                    // Fix 'Mentions Only' rooms from not having the right badge count
                    const totalCount = room.getUnreadNotificationCount('total');
                    if (totalCount < newCount) {
                        room.setUnreadNotificationCount('total', newCount);
                    }
                }
            }
        });

        // Like above, we have to listen for read receipts from ourselves in order to
        // correctly handle notification counts on encrypted rooms.
        // This fixes https://github.com/vector-im/element-web/issues/9421
        this.on("Room.receipt", (event, room) => {
            if (room && this.isRoomEncrypted(room.roomId)) {
                // Figure out if we've read something or if it's just informational
                const content = event.getContent();
                const isSelf = Object.keys(content).filter(eid => {
                    return Object.keys(content[eid]['m.read']).includes(this.getUserId());
                }).length > 0;

                if (!isSelf) return;

                // Work backwards to determine how many events are unread. We also set
                // a limit for how back we'll look to avoid spinning CPU for too long.
                // If we hit the limit, we assume the count is unchanged.
                const maxHistory = 20;
                const events = room.getLiveTimeline().getEvents();

                let highlightCount = 0;

                for (let i = events.length - 1; i >= 0; i--) {
                    if (i === events.length - maxHistory) return; // limit reached

                    const event = events[i];

                    if (room.hasUserReadEvent(this.getUserId(), event.getId())) {
                        // If the user has read the event, then the counting is done.
                        break;
                    }

                    const pushActions = this.getPushActionsForEvent(event);
                    highlightCount += pushActions.tweaks &&
                    pushActions.tweaks.highlight ? 1 : 0;
                }

                // Note: we don't need to handle 'total' notifications because the counts
                // will come from the server.
                room.setUnreadNotificationCount("highlight", highlightCount);
            }
        });
    }

    /**
     * Try to rehydrate a device if available.  The client must have been
     * initialized with a `cryptoCallback.getDehydrationKey` option, and this
     * function must be called before initCrypto and startClient are called.
     *
     * @return {Promise<string>} Resolves to undefined if a device could not be dehydrated, or
     *     to the new device ID if the dehydration was successful.
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public async rehydrateDevice(): Promise<string> {
        if (this.crypto) {
            throw new Error("Cannot rehydrate device after crypto is initialized");
        }

        if (!this.cryptoCallbacks.getDehydrationKey) {
            return;
        }

        const getDeviceResult = await this.getDehydratedDevice();
        if (!getDeviceResult) {
            return;
        }

        if (!getDeviceResult.device_data || !getDeviceResult.device_id) {
            logger.info("no dehydrated device found");
            return;
        }

        const account = new global.Olm.Account();
        try {
            const deviceData = getDeviceResult.device_data;
            if (deviceData.algorithm !== DEHYDRATION_ALGORITHM) {
                logger.warn("Wrong algorithm for dehydrated device");
                return;
            }
            logger.log("unpickling dehydrated device");
            const key = await this.cryptoCallbacks.getDehydrationKey(
                deviceData,
                (k) => {
                    // copy the key so that it doesn't get clobbered
                    account.unpickle(new Uint8Array(k), deviceData.account);
                },
            );
            account.unpickle(key, deviceData.account);
            logger.log("unpickled device");

            const rehydrateResult = await this.http.authedRequest(
                undefined,
                "POST",
                "/dehydrated_device/claim",
                undefined,
                {
                    device_id: getDeviceResult.device_id,
                },
                {
                    prefix: "/_matrix/client/unstable/org.matrix.msc2697.v2",
                },
            );

            if (rehydrateResult.success === true) {
                this.deviceId = getDeviceResult.device_id;
                logger.info("using dehydrated device");
                const pickleKey = this.pickleKey || "DEFAULT_KEY";
                this.exportedOlmDeviceToImport = {
                    pickledAccount: account.pickle(pickleKey),
                    sessions: [],
                    pickleKey: pickleKey,
                };
                account.free();
                return this.deviceId;
            } else {
                account.free();
                logger.info("not using dehydrated device");
                return;
            }
        } catch (e) {
            account.free();
            logger.warn("could not unpickle", e);
        }
    }

    /**
     * Get the current dehydrated device, if any
     * @return {Promise} A promise of an object containing the dehydrated device
     */
    public async getDehydratedDevice(): Promise<IDehydratedDevice> {
        try {
            return await this.http.authedRequest(
                undefined,
                "GET",
                "/dehydrated_device",
                undefined, undefined,
                {
                    prefix: "/_matrix/client/unstable/org.matrix.msc2697.v2",
                },
            );
        } catch (e) {
            logger.info("could not get dehydrated device", e.toString());
            return;
        }
    }

    /**
     * Set the dehydration key.  This will also periodically dehydrate devices to
     * the server.
     *
     * @param {Uint8Array} key the dehydration key
     * @param {IDehydratedDeviceKeyInfo} [keyInfo] Information about the key.  Primarily for
     *     information about how to generate the key from a passphrase.
     * @param {string} [deviceDisplayName] The device display name for the
     *     dehydrated device.
     * @return {Promise} A promise that resolves when the dehydrated device is stored.
     */
    public async setDehydrationKey(key: Uint8Array, keyInfo: IDehydratedDeviceKeyInfo, deviceDisplayName?: string): Promise<void> {
        if (!this.crypto) {
            logger.warn('not dehydrating device if crypto is not enabled');
            return;
        }
        // XXX: Private member access.
        return await this.crypto._dehydrationManager.setKeyAndQueueDehydration(
            key, keyInfo, deviceDisplayName,
        );
    }

    /**
     * Creates a new dehydrated device (without queuing periodic dehydration)
     * @param {Uint8Array} key the dehydration key
     * @param {IDehydratedDeviceKeyInfo} [keyInfo] Information about the key.  Primarily for
     *     information about how to generate the key from a passphrase.
     * @param {string} [deviceDisplayName] The device display name for the
     *     dehydrated device.
     * @return {Promise<String>} the device id of the newly created dehydrated device
     */
    public async createDehydratedDevice(key: Uint8Array, keyInfo: IDehydratedDeviceKeyInfo, deviceDisplayName?: string): Promise<string> {
        if (!this.crypto) {
            logger.warn('not dehydrating device if crypto is not enabled');
            return;
        }
        await this.crypto._dehydrationManager.setKey(
            key, keyInfo, deviceDisplayName,
        );
        // XXX: Private member access.
        return await this.crypto._dehydrationManager.dehydrateDevice();
    }

    public async exportDevice(): Promise<IExportedDevice> {
        if (!this.crypto) {
            logger.warn('not exporting device if crypto is not enabled');
            return;
        }
        return {
            userId: this.credentials.userId,
            deviceId: this.deviceId,
            // XXX: Private member access.
            olmDevice: await this.crypto._olmDevice.export(),
        };
    }

    /**
     * Clear any data out of the persistent stores used by the client.
     *
     * @returns {Promise} Promise which resolves when the stores have been cleared.
     */
    public clearStores(): Promise<void> {
        if (this.clientRunning) {
            throw new Error("Cannot clear stores while client is running");
        }

        const promises = [];

        promises.push(this.store.deleteAllData());
        if (this.cryptoStore) {
            promises.push(this.cryptoStore.deleteAllData());
        }
        return Promise.all(promises).then(); // .then to fix types
    }

    /**
     * Get the user-id of the logged-in user
     *
     * @return {?string} MXID for the logged-in user, or null if not logged in
     */
    public getUserId(): string {
        if (this.credentials && this.credentials.userId) {
            return this.credentials.userId;
        }
        return null;
    }

    /**
     * Get the domain for this client's MXID
     * @return {?string} Domain of this MXID
     */
    public getDomain(): string {
        if (this.credentials && this.credentials.userId) {
            return this.credentials.userId.replace(/^.*?:/, '');
        }
        return null;
    }

    /**
     * Get the local part of the current user ID e.g. "foo" in "@foo:bar".
     * @return {?string} The user ID localpart or null.
     */
    public getUserIdLocalpart(): string {
        if (this.credentials && this.credentials.userId) {
            return this.credentials.userId.split(":")[0].substring(1);
        }
        return null;
    }

    /**
     * Get the device ID of this client
     * @return {?string} device ID
     */
    public getDeviceId(): string {
        return this.deviceId;
    }

    /**
     * Check if the runtime environment supports VoIP calling.
     * @return {boolean} True if VoIP is supported.
     */
    public supportsVoip(): boolean {
        return this.canSupportVoip;
    }

    /**
     * Set whether VoIP calls are forced to use only TURN
     * candidates. This is the same as the forceTURN option
     * when creating the client.
     * @param {boolean} force True to force use of TURN servers
     */
    public setForceTURN(force: boolean) {
        this.forceTURN = force;
    }

    /**
     * Set whether to advertise transfer support to other parties on Matrix calls.
     * @param {boolean} support True to advertise the 'm.call.transferee' capability
     */
    public setSupportsCallTransfer(support: boolean) {
        this.supportsCallTransfer = support;
    }

    /**
     * Creates a new call.
     * The place*Call methods on the returned call can be used to actually place a call
     *
     * @param {string} roomId The room the call is to be placed in.
     * @return {MatrixCall} the call or null if the browser doesn't support calling.
     */
    public createCall(roomId: string): MatrixCall {
        return createNewMatrixCall(this, roomId);
    }

    /**
     * Get the current sync state.
     * @return {?SyncState} the sync state, which may be null.
     * @see module:client~MatrixClient#event:"sync"
     */
    public getSyncState(): SyncState {
        if (!this.syncApi) {
            return null;
        }
        return this.syncApi.getSyncState();
    }

    /**
     * Returns the additional data object associated with
     * the current sync state, or null if there is no
     * such data.
     * Sync errors, if available, are put in the 'error' key of
     * this object.
     * @return {?Object}
     */
    public getSyncStateData(): any { // TODO: Unify types.
        if (!this.syncApi) {
            return null;
        }
        return this.syncApi.getSyncStateData();
    }

    /**
     * Whether the initial sync has completed.
     * @return {boolean} True if at least one sync has happened.
     */
    public isInitialSyncComplete(): boolean {
        const state = this.getSyncState();
        if (!state) {
            return false;
        }
        return state === SyncState.Prepared || state === SyncState.Syncing;
    }

    /**
     * Return whether the client is configured for a guest account.
     * @return {boolean} True if this is a guest access_token (or no token is supplied).
     */
    public isGuest(): boolean {
        return this.isGuestAccount;
    }

    /**
     * Set whether this client is a guest account. <b>This method is experimental
     * and may change without warning.</b>
     * @param {boolean} guest True if this is a guest account.
     */
    public setGuest(guest: boolean) {
        // EXPERIMENTAL:
        // If the token is a macaroon, it should be encoded in it that it is a 'guest'
        // access token, which means that the SDK can determine this entirely without
        // the dev manually flipping this flag.
        this.isGuestAccount = guest;
    }

    /**
     * Return the provided scheduler, if any.
     * @return {?module:scheduler~MatrixScheduler} The scheduler or null
     */
    public getScheduler(): MatrixScheduler {
        return this.scheduler;
    }

    /**
     * Retry a backed off syncing request immediately. This should only be used when
     * the user <b>explicitly</b> attempts to retry their lost connection.
     * @return {boolean} True if this resulted in a request being retried.
     */
    public retryImmediately(): boolean {
        return this.syncApi.retryImmediately();
    }

    /**
     * Return the global notification EventTimelineSet, if any
     *
     * @return {EventTimelineSet} the globl notification EventTimelineSet
     */
    public getNotifTimelineSet(): EventTimelineSet {
        return this.notifTimelineSet;
    }

    /**
     * Set the global notification EventTimelineSet
     *
     * @param {EventTimelineSet} set
     */
    public setNotifTimelineSet(set: EventTimelineSet) {
        this.notifTimelineSet = set;
    }

    /**
     * Gets the capabilities of the homeserver. Always returns an object of
     * capability keys and their options, which may be empty.
     * @param {boolean} fresh True to ignore any cached values.
     * @return {Promise} Resolves to the capabilities of the homeserver
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public getCapabilities(fresh = false): Promise<Record<string, any>> {
        const now = new Date().getTime();

        if (this.cachedCapabilities && !fresh) {
            if (now < this.cachedCapabilities.expiration) {
                logger.log("Returning cached capabilities");
                return Promise.resolve(this.cachedCapabilities.capabilities);
            }
        }

        // We swallow errors because we need a default object anyhow
        return this.http.authedRequest(
            undefined, "GET", "/capabilities",
        ).catch((e) => {
            logger.error(e);
            return null; // otherwise consume the error
        }).then((r) => {
            if (!r) r = {};
            const capabilities = r["capabilities"] || {};

            // If the capabilities missed the cache, cache it for a shorter amount
            // of time to try and refresh them later.
            const cacheMs = Object.keys(capabilities).length
                ? CAPABILITIES_CACHE_MS
                : 60000 + (Math.random() * 5000);

            this.cachedCapabilities = {
                capabilities: capabilities,
                expiration: now + cacheMs,
            };

            logger.log("Caching capabilities: ", capabilities);
            return capabilities;
        });
    }

    /**
     * Initialise support for end-to-end encryption in this client
     *
     * You should call this method after creating the matrixclient, but *before*
     * calling `startClient`, if you want to support end-to-end encryption.
     *
     * It will return a Promise which will resolve when the crypto layer has been
     * successfully initialised.
     */
    public async initCrypto(): Promise<void> {
        if (!isCryptoAvailable()) {
            throw new Error(
                `End-to-end encryption not supported in this js-sdk build: did ` +
                `you remember to load the olm library?`,
            );
        }

        if (this.crypto) {
            logger.warn("Attempt to re-initialise e2e encryption on MatrixClient");
            return;
        }

        if (!this.sessionStore) {
            // this is temporary, the sessionstore is supposed to be going away
            throw new Error(`Cannot enable encryption: no sessionStore provided`);
        }
        if (!this.cryptoStore) {
            // the cryptostore is provided by sdk.createClient, so this shouldn't happen
            throw new Error(`Cannot enable encryption: no cryptoStore provided`);
        }

        logger.log("Crypto: Starting up crypto store...");
        await this.cryptoStore.startup();

        // initialise the list of encrypted rooms (whether or not crypto is enabled)
        logger.log("Crypto: initialising roomlist...");
        await this.roomList.init();

        const userId = this.getUserId();
        if (userId === null) {
            throw new Error(
                `Cannot enable encryption on MatrixClient with unknown userId: ` +
                `ensure userId is passed in createClient().`,
            );
        }
        if (this.deviceId === null) {
            throw new Error(
                `Cannot enable encryption on MatrixClient with unknown deviceId: ` +
                `ensure deviceId is passed in createClient().`,
            );
        }

        const crypto = new Crypto(
            this,
            this.sessionStore,
            userId, this.deviceId,
            this.store,
            this.cryptoStore,
            this.roomList,
            this.verificationMethods,
        );

        this.reEmitter.reEmit(crypto, [
            "crypto.keyBackupFailed",
            "crypto.keyBackupSessionsRemaining",
            "crypto.roomKeyRequest",
            "crypto.roomKeyRequestCancellation",
            "crypto.warning",
            "crypto.devicesUpdated",
            "crypto.willUpdateDevices",
            "deviceVerificationChanged",
            "userTrustStatusChanged",
            "crossSigning.keysChanged",
        ]);

        logger.log("Crypto: initialising crypto object...");
        await crypto.init({
            exportedOlmDevice: this.exportedOlmDeviceToImport,
            pickleKey: this.pickleKey,
        });
        delete this.exportedOlmDeviceToImport;

        this.olmVersion = Crypto.getOlmVersion();

        // if crypto initialisation was successful, tell it to attach its event
        // handlers.
        crypto.registerEventHandlers(this);
        this.crypto = crypto;
    }

    /**
     * Is end-to-end crypto enabled for this client.
     * @return {boolean} True if end-to-end is enabled.
     */
    public isCryptoEnabled(): boolean {
        return !!this.crypto;
    }

    /**
     * Get the Ed25519 key for this device
     *
     * @return {?string} base64-encoded ed25519 key. Null if crypto is
     *    disabled.
     */
    public getDeviceEd25519Key(): string {
        if (!this.crypto) return null;
        return this.crypto.getDeviceEd25519Key();
    }

    /**
     * Get the Curve25519 key for this device
     *
     * @return {?string} base64-encoded curve25519 key. Null if crypto is
     *    disabled.
     */
    public getDeviceCurve25519Key(): string {
        if (!this.crypto) return null;
        return this.crypto.getDeviceCurve25519Key();
    }

    /**
     * Upload the device keys to the homeserver.
     * @return {Promise<void>} A promise that will resolve when the keys are uploaded.
     */
    public uploadKeys(): Promise<void> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        return this.crypto.uploadDeviceKeys();
    }

    /**
     * Download the keys for a list of users and stores the keys in the session
     * store.
     * @param {Array} userIds The users to fetch.
     * @param {bool} forceDownload Always download the keys even if cached.
     *
     * @return {Promise} A promise which resolves to a map userId->deviceId->{@link
        * module:crypto~DeviceInfo|DeviceInfo}.
     */
    public downloadKeys(userIds: string[], forceDownload: boolean): Promise<Record<string, Record<string, DeviceInfo>>> {
        if (!this.crypto) {
            return Promise.reject(new Error("End-to-end encryption disabled"));
        }
        return this.crypto.downloadKeys(userIds, forceDownload);
    }

    /**
     * Get the stored device keys for a user id
     *
     * @param {string} userId the user to list keys for.
     *
     * @return {module:crypto/deviceinfo[]} list of devices
     */
    public getStoredDevicesForUser(userId: string): DeviceInfo[] {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getStoredDevicesForUser(userId) || [];
    }

    /**
     * Get the stored device key for a user id and device id
     *
     * @param {string} userId the user to list keys for.
     * @param {string} deviceId unique identifier for the device
     *
     * @return {module:crypto/deviceinfo} device or null
     */
    public getStoredDevice(userId: string, deviceId: string): DeviceInfo {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getStoredDevice(userId, deviceId) || null;
    }

    /**
     * Mark the given device as verified
     *
     * @param {string} userId owner of the device
     * @param {string} deviceId unique identifier for the device or user's
     * cross-signing public key ID.
     *
     * @param {boolean=} verified whether to mark the device as verified. defaults
     *   to 'true'.
     *
     * @returns {Promise}
     *
     * @fires module:client~event:MatrixClient"deviceVerificationChanged"
     */
    public setDeviceVerified(userId: string, deviceId: string, verified = true): Promise<void> {
        const prom = this.setDeviceVerification(userId, deviceId, verified, null, null);

        // if one of the user's own devices is being marked as verified / unverified,
        // check the key backup status, since whether or not we use this depends on
        // whether it has a signature from a verified device
        if (userId == this.credentials.userId) {
            this.crypto.checkKeyBackup();
        }
        return prom;
    }

    /**
     * Mark the given device as blocked/unblocked
     *
     * @param {string} userId owner of the device
     * @param {string} deviceId unique identifier for the device or user's
     * cross-signing public key ID.
     *
     * @param {boolean=} blocked whether to mark the device as blocked. defaults
     *   to 'true'.
     *
     * @returns {Promise}
     *
     * @fires module:client~event:MatrixClient"deviceVerificationChanged"
     */
    public setDeviceBlocked(userId: string, deviceId: string, blocked = true): Promise<void> {
        return this.setDeviceVerification(userId, deviceId, null, blocked, null);
    }

    /**
     * Mark the given device as known/unknown
     *
     * @param {string} userId owner of the device
     * @param {string} deviceId unique identifier for the device or user's
     * cross-signing public key ID.
     *
     * @param {boolean=} known whether to mark the device as known. defaults
     *   to 'true'.
     *
     * @returns {Promise}
     *
     * @fires module:client~event:MatrixClient"deviceVerificationChanged"
     */
    public setDeviceKnown(userId: string, deviceId: string, known = true): Promise<void> {
        return this.setDeviceVerification(userId, deviceId, null, null, known);
    }

    private async setDeviceVerification(userId: string, deviceId: string, verified: boolean, blocked: boolean, known: boolean): Promise<void> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        await this.crypto.setDeviceVerification(userId, deviceId, verified, blocked, known);
    }

    /**
     * Request a key verification from another user, using a DM.
     *
     * @param {string} userId the user to request verification with
     * @param {string} roomId the room to use for verification
     *
     * @returns {Promise<module:crypto/verification/request/VerificationRequest>} resolves to a VerificationRequest
     *    when the request has been sent to the other party.
     */
    public requestVerificationDM(userId: string, roomId: string): Promise<VerificationRequest> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.requestVerificationDM(userId, roomId);
    }

    /**
     * Finds a DM verification request that is already in progress for the given room id
     *
     * @param {string} roomId the room to use for verification
     *
     * @returns {module:crypto/verification/request/VerificationRequest?} the VerificationRequest that is in progress, if any
     */
    public findVerificationRequestDMInProgress(roomId: string): VerificationRequest {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.findVerificationRequestDMInProgress(roomId);
    }

    /**
     * Returns all to-device verification requests that are already in progress for the given user id
     *
     * @param {string} userId the ID of the user to query
     *
     * @returns {module:crypto/verification/request/VerificationRequest[]} the VerificationRequests that are in progress
     */
    public getVerificationRequestsToDeviceInProgress(userId: string): VerificationRequest[] {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getVerificationRequestsToDeviceInProgress(userId);
    }

    /**
     * Request a key verification from another user.
     *
     * @param {string} userId the user to request verification with
     * @param {Array} devices array of device IDs to send requests to.  Defaults to
     *    all devices owned by the user
     *
     * @returns {Promise<module:crypto/verification/request/VerificationRequest>} resolves to a VerificationRequest
     *    when the request has been sent to the other party.
     */
    public requestVerification(userId: string, devices: string[]): Promise<VerificationRequest> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.requestVerification(userId, devices);
    }

    /**
     * Begin a key verification.
     *
     * @param {string} method the verification method to use
     * @param {string} userId the user to verify keys with
     * @param {string} deviceId the device to verify
     *
     * @returns {Verification} a verification object
     */
    public beginKeyVerification(method: string, userId: string, deviceId: string): Verification {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.beginKeyVerification(method, userId, deviceId);
    }

    /**
     * Set the global override for whether the client should ever send encrypted
     * messages to unverified devices.  This provides the default for rooms which
     * do not specify a value.
     *
     * @param {boolean} value whether to blacklist all unverified devices by default
     */
    public setGlobalBlacklistUnverifiedDevices(value: boolean) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.setGlobalBlacklistUnverifiedDevices(value);
    }

    /**
     * @return {boolean} whether to blacklist all unverified devices by default
     */
    public getGlobalBlacklistUnverifiedDevices(): boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getGlobalBlacklistUnverifiedDevices();
    }

    /**
     * Set whether sendMessage in a room with unknown and unverified devices
     * should throw an error and not send them message. This has 'Global' for
     * symmetry with setGlobalBlacklistUnverifiedDevices but there is currently
     * no room-level equivalent for this setting.
     *
     * This API is currently UNSTABLE and may change or be removed without notice.
     *
     * @param {boolean} value whether error on unknown devices
     */
    public setGlobalErrorOnUnknownDevices(value: boolean) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.setGlobalErrorOnUnknownDevices(value);
    }

    /**
     * @return {boolean} whether to error on unknown devices
     *
     * This API is currently UNSTABLE and may change or be removed without notice.
     */
    public getGlobalErrorOnUnknownDevices(): boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getGlobalErrorOnUnknownDevices();
    }

    /**
     * Get the user's cross-signing key ID.
     *
     * The cross-signing API is currently UNSTABLE and may change without notice.
     *
     * @param {CrossSigningKey} [type=master] The type of key to get the ID of.  One of
     *     "master", "self_signing", or "user_signing".  Defaults to "master".
     *
     * @returns {string} the key ID
     */
    public getCrossSigningId(type = CrossSigningKey.Master): string {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getCrossSigningId(type);
    }

    /**
     * Get the cross signing information for a given user.
     *
     * The cross-signing API is currently UNSTABLE and may change without notice.
     *
     * @param {string} userId the user ID to get the cross-signing info for.
     *
     * @returns {CrossSigningInfo} the cross signing information for the user.
     */
    public getStoredCrossSigningForUser(userId: string): CrossSigningInfo {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getStoredCrossSigningForUser(userId);
    }

    /**
     * Check whether a given user is trusted.
     *
     * The cross-signing API is currently UNSTABLE and may change without notice.
     *
     * @param {string} userId The ID of the user to check.
     *
     * @returns {UserTrustLevel}
     */
    public checkUserTrust(userId: string): UserTrustLevel {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.checkUserTrust(userId);
    }

    /**
     * Check whether a given device is trusted.
     *
     * The cross-signing API is currently UNSTABLE and may change without notice.
     *
     * @function module:client~MatrixClient#checkDeviceTrust
     * @param {string} userId The ID of the user whose devices is to be checked.
     * @param {string} deviceId The ID of the device to check
     *
     * @returns {IDeviceTrustLevel}
     */
    public checkDeviceTrust(userId: string, deviceId: string): IDeviceTrustLevel {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.checkDeviceTrust(userId, deviceId);
    }

    /**
     * Check the copy of our cross-signing key that we have in the device list and
     * see if we can get the private key. If so, mark it as trusted.
     */
    public checkOwnCrossSigningTrust() {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.checkOwnCrossSigningTrust();
    }

    /**
     * Checks that a given cross-signing private key matches a given public key.
     * This can be used by the getCrossSigningKey callback to verify that the
     * private key it is about to supply is the one that was requested.
     * @param {Uint8Array} privateKey The private key
     * @param {string} expectedPublicKey The public key
     * @returns {boolean} true if the key matches, otherwise false
     */
    public checkCrossSigningPrivateKey(privateKey: Uint8Array, expectedPublicKey: string): boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.checkCrossSigningPrivateKey(privateKey, expectedPublicKey);
    }

    public legacyDeviceVerification(userId: string, deviceId: string, method: string): Promise<VerificationRequest> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.legacyDeviceVerification(userId, deviceId, method);
    }

    /**
     * Perform any background tasks that can be done before a message is ready to
     * send, in order to speed up sending of the message.
     * @param {module:models/room} room the room the event is in
     */
    public prepareToEncrypt(room: Room) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.prepareToEncrypt(room);
    }

    /**
     * Checks whether cross signing:
     * - is enabled on this account and trusted by this device
     * - has private keys either cached locally or stored in secret storage
     *
     * If this function returns false, bootstrapCrossSigning() can be used
     * to fix things such that it returns true. That is to say, after
     * bootstrapCrossSigning() completes successfully, this function should
     * return true.
     * @return {bool} True if cross-signing is ready to be used on this device
     */
    public isCrossSigningReady(): boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.isCrossSigningReady();
    }

    /**
     * Bootstrap cross-signing by creating keys if needed. If everything is already
     * set up, then no changes are made, so this is safe to run to ensure
     * cross-signing is ready for use.
     *
     * This function:
     * - creates new cross-signing keys if they are not found locally cached nor in
     *   secret storage (if it has been setup)
     *
     * The cross-signing API is currently UNSTABLE and may change without notice.
     *
     * @param {function} opts.authUploadDeviceSigningKeys Function
     * called to await an interactive auth flow when uploading device signing keys.
     * @param {bool} [opts.setupNewCrossSigning] Optional. Reset even if keys
     * already exist.
     * Args:
     *     {function} A function that makes the request requiring auth. Receives the
     *     auth data as an object. Can be called multiple times, first with an empty
     *     authDict, to obtain the flows.
     */
    public bootstrapCrossSigning(opts: {
        authUploadDeviceSigningKeys: (makeRequest: (authData: any) => void) => Promise<void>,
        setupNewCrossSigning?: boolean,
    }) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.bootstrapCrossSigning(opts);
    }
    /**
     * Whether to trust a others users signatures of their devices.
     * If false, devices will only be considered 'verified' if we have
     * verified that device individually (effectively disabling cross-signing).
     *
     * Default: true
     *
     * @return {bool} True if trusting cross-signed devices
     */
    public getCryptoTrustCrossSignedDevices() : boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getCryptoTrustCrossSignedDevices();
    }

    /**
     * See getCryptoTrustCrossSignedDevices

     * This may be set before initCrypto() is called to ensure no races occur.
     *
     * @param {bool} val True to trust cross-signed devices
     */
    public setCryptoTrustCrossSignedDevices(val: boolean) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.setCryptoTrustCrossSignedDevices(val);
    }

    /**
     * Counts the number of end to end session keys that are waiting to be backed up
     * @returns {Promise<int>} Resolves to the number of sessions requiring backup
     */
    public countSessionsNeedingBackup(): Promise<number> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.countSessionsNeedingBackup();
    }

    /**
     * Get information about the encryption of an event
     *
     * @param {module:models/event.MatrixEvent} event event to be checked
     * @returns {IEncryptedEventInfo} The event information.
     */
    public getEventEncryptionInfo(event: MatrixEvent): IEncryptedEventInfo {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getEventEncryptionInfo(event);
    }

    /**
     * Create a recovery key from a user-supplied passphrase.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {string} password Passphrase string that can be entered by the user
     *     when restoring the backup as an alternative to entering the recovery key.
     *     Optional.
     * @returns {Promise<Object>} Object with public key metadata, encoded private
     *     recovery key which should be disposed of after displaying to the user,
     *     and raw private key to avoid round tripping if needed.
     */
    public createRecoveryKeyFromPassphrase(password: string): Promise<IRecoveryKey> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.createRecoveryKeyFromPassphrase(password);
    }

    /**
     * Checks whether secret storage:
     * - is enabled on this account
     * - is storing cross-signing private keys
     * - is storing session backup key (if enabled)
     *
     * If this function returns false, bootstrapSecretStorage() can be used
     * to fix things such that it returns true. That is to say, after
     * bootstrapSecretStorage() completes successfully, this function should
     * return true.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @return {bool} True if secret storage is ready to be used on this device
     */
    public isSecretStorageReady(): boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.isSecretStorageReady();
    }

    /**
     * Bootstrap Secure Secret Storage if needed by creating a default key. If everything is
     * already set up, then no changes are made, so this is safe to run to ensure secret
     * storage is ready for use.
     *
     * This function
     * - creates a new Secure Secret Storage key if no default key exists
     *   - if a key backup exists, it is migrated to store the key in the Secret
     *     Storage
     * - creates a backup if none exists, and one is requested
     * - migrates Secure Secret Storage to use the latest algorithm, if an outdated
     *   algorithm is found
     *
     * @param opts
     */
    public bootstrapSecretStorage(opts: ICreateSecretStorageOpts): Promise<void> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.bootstrapSecretStorage(opts);
    }

    /**
     * Add a key for encrypting secrets.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {string} algorithm the algorithm used by the key
     * @param {object} opts the options for the algorithm.  The properties used
     *     depend on the algorithm given.
     * @param {string} [keyName] the name of the key.  If not given, a random name will be generated.
     *
     * @return {object} An object with:
     *     keyId: {string} the ID of the key
     *     keyInfo: {object} details about the key (iv, mac, passphrase)
     */
    public addSecretStorageKey(algorithm: string, opts: IAddSecretStorageKeyOpts, keyName?: string): ISecretStorageKey {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.addSecretStorageKey(algorithm, opts, keyName);
    }

    /**
     * Check whether we have a key with a given ID.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {string} [keyId = default key's ID] The ID of the key to check
     *     for. Defaults to the default key ID if not provided.
     * @return {boolean} Whether we have the key.
     */
    public hasSecretStorageKey(keyId?:string): boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.hasSecretStorageKey(keyId);
    }

    /**
     * Store an encrypted secret on the server.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {string} name The name of the secret
     * @param {string} secret The secret contents.
     * @param {Array} keys The IDs of the keys to use to encrypt the secret or null/undefined
     *     to use the default (will throw if no default key is set).
     */
    public storeSecret(name: string, secret: string, keys?: string[]) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.storeSecret(name, secret, keys);
    }

    /**
     * Get a secret from storage.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {string} name the name of the secret
     *
     * @return {string} the contents of the secret
     */
    public getSecret(name: string): string {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getSecret(name);
    }

    /**
     * Check if a secret is stored on the server.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {string} name the name of the secret
     * @param {boolean} checkKey check if the secret is encrypted by a trusted
     *     key
     *
     * @return {object?} map of key name to key info the secret is encrypted
     *     with, or null if it is not present or not encrypted with a trusted
     *     key
     */
    public isSecretStored(name: string, checkKey: boolean): Record<string, ISecretStorageKeyInfo> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.isSecretStored(name, checkKey);
    }

    /**
     * Request a secret from another device.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {string} name the name of the secret to request
     * @param {string[]} devices the devices to request the secret from
     *
     * @return {string} the contents of the secret
     */
    public requestSecret(name: string, devices: string[]): string {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.requestSecret(name, devices);
    }

    /**
     * Get the current default key ID for encrypting secrets.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @return {string} The default key ID or null if no default key ID is set
     */
    public getDefaultSecretStorageKeyId(): string {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.getDefaultSecretStorageKeyId();
    }

    /**
     * Set the current default key ID for encrypting secrets.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {string} keyId The new default key ID
     */
    public setDefaultSecretStorageKeyId(keyId: string) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.setDefaultSecretStorageKeyId(keyId);
    }

    /**
     * Checks that a given secret storage private key matches a given public key.
     * This can be used by the getSecretStorageKey callback to verify that the
     * private key it is about to supply is the one that was requested.
     *
     * The Secure Secret Storage API is currently UNSTABLE and may change without notice.
     *
     * @param {Uint8Array} privateKey The private key
     * @param {string} expectedPublicKey The public key
     * @returns {boolean} true if the key matches, otherwise false
     */
    public checkSecretStoragePrivateKey(privateKey: Uint8Array, expectedPublicKey: string): boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.checkSecretStoragePrivateKey(privateKey, expectedPublicKey);
    }

    /**
     * Get e2e information on the device that sent an event
     *
     * @param {MatrixEvent} event event to be checked
     *
     * @return {Promise<module:crypto/deviceinfo?>}
     */
    public getEventSenderDeviceInfo(event: MatrixEvent): Promise<DeviceInfo> {
        if (!this.crypto) {
            return null;
        }
        return this.crypto.getEventSenderDeviceInfo(event);
    }

    /**
     * Check if the sender of an event is verified
     *
     * @param {MatrixEvent} event event to be checked
     *
     * @return {boolean} true if the sender of this event has been verified using
     * {@link module:client~MatrixClient#setDeviceVerified|setDeviceVerified}.
     */
    public async isEventSenderVerified(event: MatrixEvent): Promise<boolean> {
        const device = await this.getEventSenderDeviceInfo(event);
        if (!device) {
            return false;
        }
        return device.isVerified();
    }

    /**
     * Cancel a room key request for this event if one is ongoing and resend the
     * request.
     * @param  {MatrixEvent} event event of which to cancel and resend the room
     *                            key request.
     * @return {Promise} A promise that will resolve when the key request is queued
     */
    public cancelAndResendEventRoomKeyRequest(event: MatrixEvent): Promise<void> {
        return event.cancelAndResendKeyRequest(this.crypto, this.getUserId());
    }

    /**
     * Enable end-to-end encryption for a room. This does not modify room state.
     * Any messages sent before the returned promise resolves will be sent unencrypted.
     * @param {string} roomId The room ID to enable encryption in.
     * @param {object} config The encryption config for the room.
     * @return {Promise} A promise that will resolve when encryption is set up.
     */
    public setRoomEncryption(roomId: string, config: any): Promise<void> {
        if (!this.crypto) {
            throw new Error("End-to-End encryption disabled");
        }
        return this.crypto.setRoomEncryption(roomId, config);
    }

    /**
     * Whether encryption is enabled for a room.
     * @param {string} roomId the room id to query.
     * @return {bool} whether encryption is enabled.
     */
    public isRoomEncrypted(roomId: string): boolean {
        const room = this.getRoom(roomId);
        if (!room) {
            // we don't know about this room, so can't determine if it should be
            // encrypted. Let's assume not.
            return false;
        }

        // if there is an 'm.room.encryption' event in this room, it should be
        // encrypted (independently of whether we actually support encryption)
        const ev = room.currentState.getStateEvents("m.room.encryption", "");
        if (ev) {
            return true;
        }

        // we don't have an m.room.encrypted event, but that might be because
        // the server is hiding it from us. Check the store to see if it was
        // previously encrypted.
        return this.roomList.isRoomEncrypted(roomId);
    }

    /**
     * Forces the current outbound group session to be discarded such
     * that another one will be created next time an event is sent.
     *
     * @param {string} roomId The ID of the room to discard the session for
     *
     * This should not normally be necessary.
     */
    public forceDiscardSession(roomId: string) {
        if (!this.crypto) {
            throw new Error("End-to-End encryption disabled");
        }
        this.crypto.forceDiscardSession(roomId);
    }

    /**
     * Get a list containing all of the room keys
     *
     * This should be encrypted before returning it to the user.
     *
     * @return {Promise} a promise which resolves to a list of
     *    session export objects
     */
    public exportRoomKeys(): Promise<any[]> { // TODO: Types
        if (!this.crypto) {
            return Promise.reject(new Error("End-to-end encryption disabled"));
        }
        return this.crypto.exportRoomKeys();
    }

    /**
     * Import a list of room keys previously exported by exportRoomKeys
     *
     * @param {Object[]} keys a list of session export objects
     * @param {Object} opts
     * @param {Function} opts.progressCallback called with an object that has a "stage" param
     *
     * @return {Promise} a promise which resolves when the keys
     *    have been imported
     */
    public importRoomKeys(keys: any[], opts: IImportRoomKeysOpts): Promise<void> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        return this.crypto.importRoomKeys(keys, opts);
    }

    /**
     * Force a re-check of the local key backup status against
     * what's on the server.
     *
     * @returns {Object} Object with backup info (as returned by
     *     getKeyBackupVersion) in backupInfo and
     *     trust information (as returned by isKeyBackupTrusted)
     *     in trustInfo.
     */
    public checkKeyBackup(): IKeyBackupVersion {
        return this.crypto.checkKeyBackup();
    }

    /**
     * Get information about the current key backup.
     * @returns {Promise} Information object from API or null
     */
    public getKeyBackupVersion(): Promise<IKeyBackupVersion> {
        return this.http.authedRequest(
            undefined, "GET", "/room_keys/version", undefined, undefined,
            { prefix: PREFIX_UNSTABLE },
        ).then((res) => {
            if (res.algorithm !== olmlib.MEGOLM_BACKUP_ALGORITHM) {
                const err = "Unknown backup algorithm: " + res.algorithm;
                return Promise.reject(err);
            } else if (!(typeof res.auth_data === "object")
                || !res.auth_data.public_key) {
                const err = "Invalid backup data returned";
                return Promise.reject(err);
            } else {
                return res;
            }
        }).catch((e) => {
            if (e.errcode === 'M_NOT_FOUND') {
                return null;
            } else {
                throw e;
            }
        });
    }

    /**
     * @param {object} info key backup info dict from getKeyBackupVersion()
     * @return {object} {
     *     usable: [bool], // is the backup trusted, true iff there is a sig that is valid & from a trusted device
     *     sigs: [
     *         valid: [bool],
     *         device: [DeviceInfo],
     *     ]
     * }
     */
    public isKeyBackupTrusted(info: IKeyBackupVersion): IKeyBackupTrustInfo {
        return this.crypto.isKeyBackupTrusted(info);
    }

    /**
     * @returns {bool} true if the client is configured to back up keys to
     *     the server, otherwise false. If we haven't completed a successful check
     *     of key backup status yet, returns null.
     */
    public getKeyBackupEnabled(): boolean {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        // XXX: Private member access
        if (!this.crypto._checkedForBackup) {
            return null;
        }
        return Boolean(this.crypto.backupKey);
    }

    /**
     * Enable backing up of keys, using data previously returned from
     * getKeyBackupVersion.
     *
     * @param {object} info Backup information object as returned by getKeyBackupVersion
     */
    public enableKeyBackup(info: IKeyBackupVersion) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        this.crypto.backupInfo = info;
        if (this.crypto.backupKey) this.crypto.backupKey.free();
        this.crypto.backupKey = new global.Olm.PkEncryption();
        this.crypto.backupKey.set_recipient_key(info.auth_data.public_key);

        this.emit('crypto.keyBackupStatus', true);

        // There may be keys left over from a partially completed backup, so
        // schedule a send to check.
        this.crypto.scheduleKeyBackupSend();
    }

    /**
     * Disable backing up of keys.
     */
    public disableKeyBackup() {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        this.crypto.backupInfo = null;
        if (this.crypto.backupKey) this.crypto.backupKey.free();
        this.crypto.backupKey = null;

        this.emit('crypto.keyBackupStatus', false);
    }

    /**
     * Set up the data required to create a new backup version.  The backup version
     * will not be created and enabled until createKeyBackupVersion is called.
     *
     * @param {string} password Passphrase string that can be entered by the user
     *     when restoring the backup as an alternative to entering the recovery key.
     *     Optional.
     * @param {boolean} [opts.secureSecretStorage = false] Whether to use Secure
     *     Secret Storage to store the key encrypting key backups.
     *     Optional, defaults to false.
     *
     * @returns {Promise<object>} Object that can be passed to createKeyBackupVersion and
     *     additionally has a 'recovery_key' member with the user-facing recovery key string.
     */
    // TODO: Verify types
    public async prepareKeyBackupVersion(password: string, opts: IKeyBackupPrepareOpts = {secureSecretStorage: false}): Promise<IKeyBackupVersion> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        const { keyInfo, encodedPrivateKey, privateKey } =
            await this.createRecoveryKeyFromPassphrase(password);

        if (opts.secureSecretStorage) {
            await this.storeSecret("m.megolm_backup.v1", encodeBase64(privateKey));
            logger.info("Key backup private key stored in secret storage");
        }

        // Reshape objects into form expected for key backup
        const authData: any = { // TODO
            public_key: keyInfo.pubkey,
        };
        if (keyInfo.passphrase) {
            authData.private_key_salt = keyInfo.passphrase.salt;
            authData.private_key_iterations = keyInfo.passphrase.iterations;
        }
        return {
            algorithm: olmlib.MEGOLM_BACKUP_ALGORITHM,
            auth_data: authData,
            recovery_key: encodedPrivateKey,
        } as any; // TODO
    }

    /**
     * Check whether the key backup private key is stored in secret storage.
     * @return {Promise<object?>} map of key name to key info the secret is
     *     encrypted with, or null if it is not present or not encrypted with a
     *     trusted key
     */
    public isKeyBackupKeyStored(): Promise<Record<string, ISecretStorageKeyInfo>> {
        return Promise.resolve(this.isSecretStored("m.megolm_backup.v1", false /* checkKey */));
    }

    /**
     * Create a new key backup version and enable it, using the information return
     * from prepareKeyBackupVersion.
     *
     * @param {object} info Info object from prepareKeyBackupVersion
     * @returns {Promise<object>} Object with 'version' param indicating the version created
     */
    // TODO: Fix types
    public async createKeyBackupVersion(info: IKeyBackupVersion): Promise<IKeyBackupVersion> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        const data = {
            algorithm: info.algorithm,
            auth_data: info.auth_data,
        };

        // Sign the backup auth data with the device key for backwards compat with
        // older devices with cross-signing. This can probably go away very soon in
        // favour of just signing with the cross-singing master key.
        // XXX: Private member access
        await this.crypto._signObject(data.auth_data);

        if (
            this.cryptoCallbacks.getCrossSigningKey &&
            // XXX: Private member access
            this.crypto._crossSigningInfo.getId()
        ) {
            // now also sign the auth data with the cross-signing master key
            // we check for the callback explicitly here because we still want to be able
            // to create an un-cross-signed key backup if there is a cross-signing key but
            // no callback supplied.
            // XXX: Private member access
            await this.crypto._crossSigningInfo.signObject(data.auth_data, "master");
        }

        const res = await this.http.authedRequest(
            undefined, "POST", "/room_keys/version", undefined, data,
            { prefix: PREFIX_UNSTABLE },
        );

        // We could assume everything's okay and enable directly, but this ensures
        // we run the same signature verification that will be used for future
        // sessions.
        await this.checkKeyBackup();
        if (!this.getKeyBackupEnabled()) {
            logger.error("Key backup not usable even though we just created it");
        }

        return res;
    }

    public deleteKeyBackupVersion(version: string): Promise<void> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        // If we're currently backing up to this backup... stop.
        // (We start using it automatically in createKeyBackupVersion
        // so this is symmetrical).
        if (this.crypto.backupInfo && this.crypto.backupInfo.version === version) {
            this.disableKeyBackup();
        }

        const path = utils.encodeUri("/room_keys/version/$version", {
            $version: version,
        });

        return this.http.authedRequest(
            undefined, "DELETE", path, undefined, undefined,
            { prefix: PREFIX_UNSTABLE },
        );
    }

    private makeKeyBackupPath(roomId: string, sessionId: string, version: string): {path: string, queryData: any} {
        let path;
        if (sessionId !== undefined) {
            path = utils.encodeUri("/room_keys/keys/$roomId/$sessionId", {
                $roomId: roomId,
                $sessionId: sessionId,
            });
        } else if (roomId !== undefined) {
            path = utils.encodeUri("/room_keys/keys/$roomId", {
                $roomId: roomId,
            });
        } else {
            path = "/room_keys/keys";
        }
        const queryData = version === undefined ? undefined : { version: version };
        return {
            path: path,
            queryData: queryData,
        };
    }

    /**
     * Back up session keys to the homeserver.
     * @param {string} roomId ID of the room that the keys are for Optional.
     * @param {string} sessionId ID of the session that the keys are for Optional.
     * @param {integer} version backup version Optional.
     * @param {object} data Object keys to send
     * @return {Promise} a promise that will resolve when the keys
     * are uploaded
     */
    // TODO: Verify types
    public sendKeyBackup(roomId: string, sessionId: string, version: string, data: any): Promise<void> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        const path = this.makeKeyBackupPath(roomId, sessionId, version);
        return this.http.authedRequest(
            undefined, "PUT", path.path, path.queryData, data,
            { prefix: PREFIX_UNSTABLE },
        );
    }

    /**
     * Marks all group sessions as needing to be backed up and schedules them to
     * upload in the background as soon as possible.
     */
    public async scheduleAllGroupSessionsForBackup() {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        await this.crypto.scheduleAllGroupSessionsForBackup();
    }

    /**
     * Marks all group sessions as needing to be backed up without scheduling
     * them to upload in the background.
     * @returns {Promise<int>} Resolves to the number of sessions requiring a backup.
     */
    public flagAllGroupSessionsForBackup(): Promise<number> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        return this.crypto.flagAllGroupSessionsForBackup();
    }

    public isValidRecoveryKey(recoveryKey: string): boolean {
        try {
            decodeRecoveryKey(recoveryKey);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Get the raw key for a key backup from the password
     * Used when migrating key backups into SSSS
     *
     * The cross-signing API is currently UNSTABLE and may change without notice.
     *
     * @param {string} password Passphrase
     * @param {object} backupInfo Backup metadata from `checkKeyBackup`
     * @return {Promise<Uint8Array>} key backup key
     */
    public keyBackupKeyFromPassword(password: string, backupInfo: IKeyBackupVersion): Promise<Uint8Array> {
        return keyFromAuthData(backupInfo.auth_data, password);
    }

    /**
     * Get the raw key for a key backup from the recovery key
     * Used when migrating key backups into SSSS
     *
     * The cross-signing API is currently UNSTABLE and may change without notice.
     *
     * @param {string} recoveryKey The recovery key
     * @return {Uint8Array} key backup key
     */
    public keyBackupKeyFromRecoveryKey(recoveryKey: string): Uint8Array {
        return decodeRecoveryKey(recoveryKey);
    }

    /**
     * Restore from an existing key backup via a passphrase.
     *
     * @param {string} password Passphrase
     * @param {string} [targetRoomId] Room ID to target a specific room.
     * Restores all rooms if omitted.
     * @param {string} [targetSessionId] Session ID to target a specific session.
     * Restores all sessions if omitted.
     * @param {object} backupInfo Backup metadata from `checkKeyBackup`
     * @param {object} opts Optional params such as callbacks
     * @return {Promise<object>} Status of restoration with `total` and `imported`
     * key counts.
     */
    // TODO: Types
    public async restoreKeyBackupWithPassword(password: string, targetRoomId: string, targetSessionId: string, backupInfo: IKeyBackupVersion, opts: IKeyBackupRestoreOpts): Promise<IKeyBackupRestoreResult> {
        const privKey = await keyFromAuthData(backupInfo.auth_data, password);
        return this.restoreKeyBackup(
            privKey, targetRoomId, targetSessionId, backupInfo, opts,
        );
    }

    /**
     * Restore from an existing key backup via a private key stored in secret
     * storage.
     *
     * @param {object} backupInfo Backup metadata from `checkKeyBackup`
     * @param {string} [targetRoomId] Room ID to target a specific room.
     * Restores all rooms if omitted.
     * @param {string} [targetSessionId] Session ID to target a specific session.
     * Restores all sessions if omitted.
     * @param {object} opts Optional params such as callbacks
     * @return {Promise<object>} Status of restoration with `total` and `imported`
     * key counts.
     */
    // TODO: Types
    public async restoreKeyBackupWithSecretStorage(backupInfo: IKeyBackupVersion, targetRoomId: string, targetSessionId: string, opts: IKeyBackupRestoreOpts): Promise<IKeyBackupRestoreResult> {
        const storedKey = await this.getSecret("m.megolm_backup.v1");

        // ensure that the key is in the right format.  If not, fix the key and
        // store the fixed version
        const fixedKey = fixBackupKey(storedKey);
        if (fixedKey) {
            const [keyId] = await this.crypto.getSecretStorageKey();
            await this.storeSecret("m.megolm_backup.v1", fixedKey, [keyId]);
        }

        const privKey = decodeBase64(fixedKey || storedKey);
        return this.restoreKeyBackup(
            privKey, targetRoomId, targetSessionId, backupInfo, opts,
        );
    }

    /**
     * Restore from an existing key backup via an encoded recovery key.
     *
     * @param {string} recoveryKey Encoded recovery key
     * @param {string} [targetRoomId] Room ID to target a specific room.
     * Restores all rooms if omitted.
     * @param {string} [targetSessionId] Session ID to target a specific session.
     * Restores all sessions if omitted.
     * @param {object} backupInfo Backup metadata from `checkKeyBackup`
     * @param {object} opts Optional params such as callbacks

     * @return {Promise<object>} Status of restoration with `total` and `imported`
     * key counts.
     */
    // TODO: Types
    public restoreKeyBackupWithRecoveryKey(recoveryKey: string, targetRoomId: string, targetSessionId: string, backupInfo: IKeyBackupVersion, opts: IKeyBackupRestoreOpts): Promise<IKeyBackupRestoreResult> {
        const privKey = decodeRecoveryKey(recoveryKey);
        return this.restoreKeyBackup(
            privKey, targetRoomId, targetSessionId, backupInfo, opts,
        );
    }

    // TODO: Types
    public async restoreKeyBackupWithCache(targetRoomId: string, targetSessionId: string, backupInfo: IKeyBackupVersion, opts: IKeyBackupRestoreOpts): Promise<IKeyBackupRestoreResult> {
        const privKey = await this.crypto.getSessionBackupPrivateKey();
        if (!privKey) {
            throw new Error("Couldn't get key");
        }
        return this.restoreKeyBackup(
            privKey, targetRoomId, targetSessionId, backupInfo, opts,
        );
    }

    private restoreKeyBackup(privKey: Uint8Array, targetRoomId: string, targetSessionId: string, backupInfo: IKeyBackupVersion, opts: IKeyBackupRestoreOpts): Promise<IKeyBackupRestoreResult> {
        const {cacheCompleteCallback, progressCallback} = opts;

        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }
        let totalKeyCount = 0;
        let keys = [];

        const path = this.makeKeyBackupPath(
            targetRoomId, targetSessionId, backupInfo.version,
        );

        const decryption = new global.Olm.PkDecryption();
        let backupPubKey;
        try {
            backupPubKey = decryption.init_with_private_key(privKey);
        } catch (e) {
            decryption.free();
            throw e;
        }

        // If the pubkey computed from the private data we've been given
        // doesn't match the one in the auth_data, the user has entered
        // a different recovery key / the wrong passphrase.
        if (backupPubKey !== backupInfo.auth_data.public_key) {
            return Promise.reject({ errcode: MatrixClient.RESTORE_BACKUP_ERROR_BAD_KEY });
        }

        // Cache the key, if possible.
        // This is async.
        this.crypto.storeSessionBackupPrivateKey(privKey)
            .catch((e) => {
                logger.warn("Error caching session backup key:", e);
            }).then(cacheCompleteCallback);

        if (progressCallback) {
            progressCallback({
                stage: "fetch",
            });
        }

        return this.http.authedRequest(
            undefined, "GET", path.path, path.queryData, undefined,
            { prefix: PREFIX_UNSTABLE },
        ).then((res) => {
            if (res.rooms) {
                // TODO: Types?
                for (const [roomId, roomData] of Object.entries<any>(res.rooms)) {
                    if (!roomData.sessions) continue;

                    totalKeyCount += Object.keys(roomData.sessions).length;
                    const roomKeys = keysFromRecoverySession(
                        roomData.sessions, decryption, roomId,
                    );
                    for (const k of roomKeys) {
                        k.room_id = roomId;
                        keys.push(k);
                    }
                }
            } else if (res.sessions) {
                totalKeyCount = Object.keys(res.sessions).length;
                keys = keysFromRecoverySession(
                    res.sessions, decryption, targetRoomId,
                );
            } else {
                totalKeyCount = 1;
                try {
                    const key = keyFromRecoverySession(res, decryption);
                    key.room_id = targetRoomId;
                    key.session_id = targetSessionId;
                    keys.push(key);
                } catch (e) {
                    logger.log("Failed to decrypt megolm session from backup", e);
                }
            }

            return this.importRoomKeys(keys, {
                progressCallback,
                untrusted: true,
                source: "backup",
            });
        }).then(() => {
            return this.crypto.setTrustedBackupPubKey(backupPubKey);
        }).then(() => {
            return { total: totalKeyCount, imported: keys.length };
        }).finally(() => {
            decryption.free();
        });
    }

    public deleteKeysFromBackup(roomId: string, sessionId: string, version: string): Promise<void> {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        const path = this.makeKeyBackupPath(roomId, sessionId, version);
        return this.http.authedRequest(
            undefined, "DELETE", path.path, path.queryData, undefined,
            { prefix: PREFIX_UNSTABLE },
        );
    }

    /**
     * Share shared-history decryption keys with the given users.
     *
     * @param {string} roomId the room for which keys should be shared.
     * @param {array} userIds a list of users to share with.  The keys will be sent to
     *     all of the user's current devices.
     */
    public async sendSharedHistoryKeys(roomId: string, userIds: string[]) {
        if (!this.crypto) {
            throw new Error("End-to-end encryption disabled");
        }

        const roomEncryption = this.roomList.getRoomEncryption(roomId);
        if (!roomEncryption) {
            // unknown room, or unencrypted room
            logger.error("Unknown room.  Not sharing decryption keys");
            return;
        }

        const deviceInfos = await this.crypto.downloadKeys(userIds);
        const devicesByUser = {};
        for (const [userId, devices] of Object.entries(deviceInfos)) {
            devicesByUser[userId] = Object.values(devices);
        }

        // XXX: Private member access
        const alg = this.crypto._getRoomDecryptor(roomId, roomEncryption.algorithm);
        if (alg.sendSharedHistoryInboundSessions) {
            await alg.sendSharedHistoryInboundSessions(devicesByUser);
        } else {
            logger.warn("Algorithm does not support sharing previous keys", roomEncryption.algorithm);
        }
    }

    /**
     * Get the group for the given group ID.
     * This function will return a valid group for any group for which a Group event
     * has been emitted.
     * @param {string} groupId The group ID
     * @return {Group} The Group or null if the group is not known or there is no data store.
     */
    public getGroup(groupId: string): Group {
        return this.store.getGroup(groupId);
    }

    /**
     * Retrieve all known groups.
     * @return {Group[]} A list of groups, or an empty list if there is no data store.
     */
    public getGroups(): Group[] {
        return this.store.getGroups();
    }

    /**
     * Get the config for the media repository.
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves with an object containing the config.
     */
    public getMediaConfig(callback?: Callback): Promise<any> { // TODO: Types
        return this.http.authedRequest(
            callback, "GET", "/config", undefined, undefined, {
                prefix: PREFIX_MEDIA_R0,
            },
        );
    }

    /**
     * Get the room for the given room ID.
     * This function will return a valid room for any room for which a Room event
     * has been emitted. Note in particular that other events, eg. RoomState.members
     * will be emitted for a room before this function will return the given room.
     * @param {string} roomId The room ID
     * @return {Room} The Room or null if it doesn't exist or there is no data store.
     */
    public getRoom(roomId: string): Room {
        return this.store.getRoom(roomId);
    }

    /**
     * Retrieve all known rooms.
     * @return {Room[]} A list of rooms, or an empty list if there is no data store.
     */
    public getRooms(): Room[] {
        return this.store.getRooms();
    }

    /**
     * Retrieve all rooms that should be displayed to the user
     * This is essentially getRooms() with some rooms filtered out, eg. old versions
     * of rooms that have been replaced or (in future) other rooms that have been
     * marked at the protocol level as not to be displayed to the user.
     * @return {Room[]} A list of rooms, or an empty list if there is no data store.
     */
    public getVisibleRooms(): Room[] {
        const allRooms = this.store.getRooms();

        const replacedRooms = new Set();
        for (const r of allRooms) {
            const createEvent = r.currentState.getStateEvents('m.room.create', '');
            // invites are included in this list and we don't know their create events yet
            if (createEvent) {
                const predecessor = createEvent.getContent()['predecessor'];
                if (predecessor && predecessor['room_id']) {
                    replacedRooms.add(predecessor['room_id']);
                }
            }
        }

        return allRooms.filter((r) => {
            const tombstone = r.currentState.getStateEvents('m.room.tombstone', '');
            if (tombstone && replacedRooms.has(r.roomId)) {
                return false;
            }
            return true;
        });
    }

    /**
     * Retrieve a user.
     * @param {string} userId The user ID to retrieve.
     * @return {?User} A user or null if there is no data store or the user does
     * not exist.
     */
    public getUser(userId: string): User {
        return this.store.getUser(userId);
    }

    /**
     * Retrieve all known users.
     * @return {User[]} A list of users, or an empty list if there is no data store.
     */
    public getUsers(): User[] {
        return this.store.getUsers();
    }

    /**
     * Set account data event for the current user.
     * It will retry the request up to 5 times.
     * @param {string} eventType The event type
     * @param {Object} content the contents object for the event
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public setAccountData(eventType: string, content: any, callback?: Callback): Promise<void> {
        const path = utils.encodeUri("/user/$userId/account_data/$type", {
            $userId: this.credentials.userId,
            $type: eventType,
        });
        const promise = retryNetworkOperation(5, () => {
            return this.http.authedRequest(undefined, "PUT", path, undefined, content);
        });
        if (callback) {
            promise.then(result => callback(null, result), callback);
        }
        return promise;
    }

    /**
     * Get account data event of given type for the current user.
     * @param {string} eventType The event type
     * @return {?object} The contents of the given account data event
     */
    public getAccountData(eventType: string): any {
        return this.store.getAccountData(eventType);
    }

    /**
     * Get account data event of given type for the current user. This variant
     * gets account data directly from the homeserver if the local store is not
     * ready, which can be useful very early in startup before the initial sync.
     * @param {string} eventType The event type
     * @return {Promise} Resolves: The contents of the given account
     * data event.
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public async getAccountDataFromServer(eventType: string): Promise<any> {
        if (this.isInitialSyncComplete()) {
            const event = this.store.getAccountData(eventType);
            if (!event) {
                return null;
            }
            // The network version below returns just the content, so this branch
            // does the same to match.
            return event.getContent();
        }
        const path = utils.encodeUri("/user/$userId/account_data/$type", {
            $userId: this.credentials.userId,
            $type: eventType,
        });
        try {
            return await this.http.authedRequest(
                undefined, "GET", path, undefined,
            );
        } catch (e) {
            if (e.data && e.data.errcode === 'M_NOT_FOUND') {
                return null;
            }
            throw e;
        }
    }

    /**
     * Gets the users that are ignored by this client
     * @returns {string[]} The array of users that are ignored (empty if none)
     */
    public getIgnoredUsers(): string[] {
        const event = this.getAccountData("m.ignored_user_list");
        if (!event || !event.getContent() || !event.getContent()["ignored_users"]) return [];
        return Object.keys(event.getContent()["ignored_users"]);
    }

    /**
     * Sets the users that the current user should ignore.
     * @param {string[]} userIds the user IDs to ignore
     * @param {module:client.callback} [callback] Optional.
     * @return {Promise} Resolves: Account data event
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public setIgnoredUsers(userIds: string[], callback?: Callback): Promise<any> {
        const content = { ignored_users: {} };
        userIds.map((u) => content.ignored_users[u] = {});
        return this.setAccountData("m.ignored_user_list", content, callback);
    }

    /**
     * Gets whether or not a specific user is being ignored by this client.
     * @param {string} userId the user ID to check
     * @returns {boolean} true if the user is ignored, false otherwise
     */
    public isUserIgnored(userId: string): boolean {
        return this.getIgnoredUsers().includes(userId);
    }

    /**
     * Join a room. If you have already joined the room, this will no-op.
     * @param {string} roomIdOrAlias The room ID or room alias to join.
     * @param {Object} opts Options when joining the room.
     * @param {boolean} opts.syncRoom True to do a room initial sync on the resulting
     * room. If false, the <strong>returned Room object will have no current state.
     * </strong> Default: true.
     * @param {boolean} opts.inviteSignUrl If the caller has a keypair 3pid invite, the signing URL is passed in this parameter.
     * @param {string[]} opts.viaServers The server names to try and join through in addition to those that are automatically chosen.
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: Room object.
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public async joinRoom(roomIdOrAlias: string, opts: IJoinRoomOpts, callback?: Callback): Promise<Room> {
        // to help people when upgrading..
        if (utils.isFunction(opts)) {
            throw new Error("Expected 'opts' object, got function.");
        }
        opts = opts || {};
        if (opts.syncRoom === undefined) {
            opts.syncRoom = true;
        }

        const room = this.getRoom(roomIdOrAlias);
        if (room && room.hasMembershipState(this.credentials.userId, "join")) {
            return Promise.resolve(room);
        }

        let signPromise = Promise.resolve();

        if (opts.inviteSignUrl) {
            signPromise = this.http.requestOtherUrl(
                undefined, 'POST',
                opts.inviteSignUrl, { mxid: this.credentials.userId },
            );
        }

        const queryString = {};
        if (opts.viaServers) {
            queryString["server_name"] = opts.viaServers;
        }

        const reqOpts = { qsStringifyOptions: { arrayFormat: 'repeat' } };

        try {
            const data: any = {};
            const signedInviteObj = await signPromise;
            if (signedInviteObj) {
                data['third_party_signed'] = signedInviteObj;
            }

            const path = utils.encodeUri("/join/$roomid", {$roomid: roomIdOrAlias});
            const res = await this.http.authedRequest(undefined, "POST", path, queryString, data, reqOpts);

            const roomId = res['room_id'];
            const syncApi = new SyncApi(this, this.clientOpts);
            const room = syncApi.createRoom(roomId);
            if (opts.syncRoom) {
                // v2 will do this for us
                // return syncApi.syncRoom(room);
            }
            callback?.(null, room);
            return room;
        } catch (e) {
            callback?.(e);
            throw e; // rethrow for reject
        }
    }

    /**
     * Resend an event.
     * @param {MatrixEvent} event The event to resend.
     * @param {Room} room Optional. The room the event is in. Will update the
     * timeline entry if provided.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public resendEvent(event: MatrixEvent, room: Room): Promise<void> {
        this.updatePendingEventStatus(room, event, EventStatus.SENDING);
        return this.sendEvent(room, event);
    }

    /**
     * Cancel a queued or unsent event.
     *
     * @param {MatrixEvent} event   Event to cancel
     * @throws Error if the event is not in QUEUED or NOT_SENT state
     */
    public cancelPendingEvent(event: MatrixEvent) {
        if ([EventStatus.QUEUED, EventStatus.NOT_SENT].indexOf(event.status) < 0) {
            throw new Error("cannot cancel an event with status " + event.status);
        }

        // first tell the scheduler to forget about it, if it's queued
        if (this.scheduler) {
            this.scheduler.removeEventFromQueue(event);
        }

        // then tell the room about the change of state, which will remove it
        // from the room's list of pending events.
        const room = this.getRoom(event.getRoomId());
        this.updatePendingEventStatus(room, event, EventStatus.CANCELLED);
    }

    /**
     * @param {string} roomId
     * @param {string} name
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public setRoomName(roomId: string, name: string, callback?: Callback): Promise<void> {
        return this.sendStateEvent(roomId, "m.room.name", { name: name }, undefined, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} topic
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public setRoomTopic(roomId: string, topic: string, callback?: Callback): Promise<void> {
        return this.sendStateEvent(roomId, "m.room.topic", { topic: topic }, undefined, callback);
    }

    /**
     * @param {string} roomId
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public getRoomTags(roomId: string, callback?: Callback): Promise<unknown> { // TODO: Types
        const path = utils.encodeUri("/user/$userId/rooms/$roomId/tags/", {
            $userId: this.credentials.userId,
            $roomId: roomId,
        });
        return this.http.authedRequest(
            callback, "GET", path, undefined,
        );
    }

    /**
     * @param {string} roomId
     * @param {string} tagName name of room tag to be set
     * @param {object} metadata associated with that tag to be stored
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public setRoomTag(roomId: string, tagName: string, metadata: any, callback?: Callback): Promise<unknown> { // TODO: Types
        const path = utils.encodeUri("/user/$userId/rooms/$roomId/tags/$tag", {
            $userId: this.credentials.userId,
            $roomId: roomId,
            $tag: tagName,
        });
        return this.http.authedRequest(
            callback, "PUT", path, undefined, metadata,
        );
    }

    /**
     * @param {string} roomId
     * @param {string} tagName name of room tag to be removed
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public deleteRoomTag(roomId: string, tagName: string, callback?: Callback): Promise<void> {
        const path = utils.encodeUri("/user/$userId/rooms/$roomId/tags/$tag", {
            $userId: this.credentials.userId,
            $roomId: roomId,
            $tag: tagName,
        });
        return this.http.authedRequest(
            callback, "DELETE", path, undefined, undefined,
        );
    }

    /**
     * @param {string} roomId
     * @param {string} eventType event type to be set
     * @param {object} content event content
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public setRoomAccountData(roomId: string, eventType: string, content: any, callback?: Callback): Promise<void> {
        const path = utils.encodeUri("/user/$userId/rooms/$roomId/account_data/$type", {
            $userId: this.credentials.userId,
            $roomId: roomId,
            $type: eventType,
        });
        return this.http.authedRequest(
            callback, "PUT", path, undefined, content,
        );
    }

    /**
     * Set a user's power level.
     * @param {string} roomId
     * @param {string} userId
     * @param {Number} powerLevel
     * @param {MatrixEvent} event
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public setPowerLevel(roomId: string, userId: string, powerLevel: number, event: MatrixEvent, callback?: Callback): Promise<void> {
        let content = {
            users: {},
        };
        if (event && event.getType() === "m.room.power_levels") {
            // take a copy of the content to ensure we don't corrupt
            // existing client state with a failed power level change
            content = utils.deepCopy(event.getContent());
        }
        content.users[userId] = powerLevel;
        const path = utils.encodeUri("/rooms/$roomId/state/m.room.power_levels", {
            $roomId: roomId,
        });
        return this.http.authedRequest(
            callback, "PUT", path, undefined, content,
        );
    }

    /**
     * @param {string} roomId
     * @param {string} eventType
     * @param {Object} content
     * @param {string} txnId Optional.
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendEvent(roomId: string, eventType: string, content: any, txnId?: string, callback?: Callback): Promise<ISendEventResponse> {
        return this.sendCompleteEvent(roomId, {type: eventType, content}, txnId, callback);
    }

    /**
     * @param {string} roomId
     * @param {object} eventObject An object with the partial structure of an event, to which event_id, user_id, room_id and origin_server_ts will be added.
     * @param {string} txnId the txnId.
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    private sendCompleteEvent(roomId: string, eventObject: any, txnId: string, callback?: Callback): Promise<ISendEventResponse> {
        if (utils.isFunction(txnId)) {
            callback = txnId as any as Callback; // convert for legacy
            txnId = undefined;
        }

        if (!txnId) {
            txnId = this.makeTxnId();
        }

        // we always construct a MatrixEvent when sending because the store and
        // scheduler use them. We'll extract the params back out if it turns out
        // the client has no scheduler or store.
        const localEvent = new MatrixEvent(Object.assign(eventObject, {
            event_id: "~" + roomId + ":" + txnId,
            user_id: this.credentials.userId,
            sender: this.credentials.userId,
            room_id: roomId,
            origin_server_ts: new Date().getTime(),
        }));

        const room = this.getRoom(roomId);

        // if this is a relation or redaction of an event
        // that hasn't been sent yet (e.g. with a local id starting with a ~)
        // then listen for the remote echo of that event so that by the time
        // this event does get sent, we have the correct event_id
        const targetId = localEvent.getAssociatedId();
        if (targetId && targetId.startsWith("~")) {
            const target = room.getPendingEvents().find(e => e.getId() === targetId);
            target.once("Event.localEventIdReplaced", () => {
                localEvent.updateAssociatedId(target.getId());
            });
        }

        const type = localEvent.getType();
        logger.log(`sendEvent of type ${type} in ${roomId} with txnId ${txnId}`);

        localEvent.setTxnId(txnId);
        localEvent.setStatus(EventStatus.SENDING);

        // add this event immediately to the local store as 'sending'.
        if (room) {
            room.addPendingEvent(localEvent, txnId);
        }

        // addPendingEvent can change the state to NOT_SENT if it believes
        // that there's other events that have failed. We won't bother to
        // try sending the event if the state has changed as such.
        if (localEvent.status === EventStatus.NOT_SENT) {
            return Promise.reject(new Error("Event blocked by other events not yet sent"));
        }

        return this.encryptAndSendEvent(room, localEvent, callback);
    }

    /**
     * encrypts the event if necessary; adds the event to the queue, or sends it; marks the event as sent/unsent
     * @param room
     * @param event
     * @param callback
     * @returns {Promise} returns a promise which resolves with the result of the send request
     * @private
     */
    private encryptAndSendEvent(room: Room, event: MatrixEvent, callback?: Callback): Promise<ISendEventResponse> {
        // Add an extra Promise.resolve() to turn synchronous exceptions into promise rejections,
        // so that we can handle synchronous and asynchronous exceptions with the
        // same code path.
        return Promise.resolve().then(() => {
            const encryptionPromise = this.encryptEventIfNeeded(event, room);
            if (!encryptionPromise) return null;

            this.updatePendingEventStatus(room, event, EventStatus.ENCRYPTING);
            return encryptionPromise.then(() => this.updatePendingEventStatus(room, event, EventStatus.SENDING));
        }).then(() => {
            let promise: Promise<ISendEventResponse>;
            if (this.scheduler) {
                // if this returns a promise then the scheduler has control now and will
                // resolve/reject when it is done. Internally, the scheduler will invoke
                // processFn which is set to this._sendEventHttpRequest so the same code
                // path is executed regardless.
                promise = this.scheduler.queueEvent(event);
                if (promise && this.scheduler.getQueueForEvent(event).length > 1) {
                    // event is processed FIFO so if the length is 2 or more we know
                    // this event is stuck behind an earlier event.
                    this.updatePendingEventStatus(room, event, EventStatus.QUEUED);
                }
            }

            if (!promise) {
                promise = this.sendEventHttpRequest(event);
                if (room) {
                    promise = promise.then(res => {
                        room.updatePendingEvent(event, EventStatus.SENT, res['event_id']);
                        return res;
                    });
                }
            }

            return promise;
        }).then(res => {
            callback?.(null, res);
            return res;
        }).catch(err => {
            logger.error("Error sending event", err.stack || err);
            try {
                // set the error on the event before we update the status:
                // updating the status emits the event, so the state should be
                // consistent at that point.
                event.error = err;
                this.updatePendingEventStatus(room, event, EventStatus.NOT_SENT);
                // also put the event object on the error: the caller will need this
                // to resend or cancel the event
                err.event = event;

                callback?.(err);
            } catch (e) {
                logger.error("Exception in error handler!", e.stack || err);
            }
            throw err;
        });
    }

    private encryptEventIfNeeded(event: MatrixEvent, room?: Room): Promise<void> | null {
        if (event.isEncrypted()) {
            // this event has already been encrypted; this happens if the
            // encryption step succeeded, but the send step failed on the first
            // attempt.
            return null;
        }

        if (!this.isRoomEncrypted(event.getRoomId())) {
            return null;
        }

        if (!this.crypto && this.usingExternalCrypto) {
            // The client has opted to allow sending messages to encrypted
            // rooms even if the room is encrypted, and we haven't setup
            // crypto. This is useful for users of matrix-org/pantalaimon
            return null;
        }

        if (event.getType() === EventType.Reaction) {
            // For reactions, there is a very little gained by encrypting the entire
            // event, as relation data is already kept in the clear. Event
            // encryption for a reaction effectively only obscures the event type,
            // but the purpose is still obvious from the relation data, so nothing
            // is really gained. It also causes quite a few problems, such as:
            //   * triggers notifications via default push rules
            //   * prevents server-side bundling for reactions
            // The reaction key / content / emoji value does warrant encrypting, but
            // this will be handled separately by encrypting just this value.
            // See https://github.com/matrix-org/matrix-doc/pull/1849#pullrequestreview-248763642
            return null;
        }

        if (!this.crypto) {
            throw new Error(
                "This room is configured to use encryption, but your client does " +
                "not support encryption.",
            );
        }

        return this.crypto.encryptEvent(event, room);
    }

    /**
     * Returns the eventType that should be used taking encryption into account
     * for a given eventType.
     * @param {MatrixClient} client the client
     * @param {string} roomId the room for the events `eventType` relates to
     * @param {string} eventType the event type
     * @return {string} the event type taking encryption into account
     */
    private getEncryptedIfNeededEventType(roomId: string, eventType: string): string {
        if (eventType === EventType.Reaction) return eventType;
        return this.isRoomEncrypted(roomId) ? EventType.RoomMessageEncrypted : eventType;
    }

    private updatePendingEventStatus(room: Room | null, event: MatrixEvent, newStatus: EventStatus) {
        if (room) {
            room.updatePendingEvent(event, newStatus);
        } else {
            event.setStatus(newStatus);
        }
    }

    private sendEventHttpRequest(event: MatrixEvent): Promise<ISendEventResponse> {
        let txnId = event.getTxnId();
        if (!txnId) {
            txnId = this.makeTxnId();
            event.setTxnId(txnId);
        }


        const pathParams = {
            $roomId: event.getRoomId(),
            $eventType: event.getWireType(),
            $stateKey: event.getStateKey(),
            $txnId: txnId,
        };

        let path;

        if (event.isState()) {
            let pathTemplate = "/rooms/$roomId/state/$eventType";
            if (event.getStateKey() && event.getStateKey().length > 0) {
                pathTemplate = "/rooms/$roomId/state/$eventType/$stateKey";
            }
            path = utils.encodeUri(pathTemplate, pathParams);
        } else if (event.isRedaction()) {
            const pathTemplate = `/rooms/$roomId/redact/$redactsEventId/$txnId`;
            path = utils.encodeUri(pathTemplate, Object.assign({
                $redactsEventId: event.event.redacts,
            }, pathParams));
        } else {
            path = utils.encodeUri("/rooms/$roomId/send/$eventType/$txnId", pathParams);
        }

        return this.http.authedRequest(
            undefined, "PUT", path, undefined, event.getWireContent(),
        ).then((res) => {
            logger.log(`Event sent to ${event.getRoomId()} with event id ${res.event_id}`);
            return res;
        });
    }

    /**
     * @param {string} roomId
     * @param {string} eventId
     * @param {string} [txnId]  transaction id. One will be made up if not
     *    supplied.
     * @param {object|module:client.callback} cbOrOpts
     *    Options to pass on, may contain `reason`.
     *    Can be callback for backwards compatibility.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public redactEvent(roomId: string, eventId: string, txnId?: string, cbOrOpts?: Callback | IRedactOpts): Promise<ISendEventResponse> {
        const opts = typeof(cbOrOpts) === 'object' ? cbOrOpts : {};
        const reason = opts.reason;
        const callback = typeof(cbOrOpts) === 'function' ? cbOrOpts : undefined;
        return this.sendCompleteEvent(roomId, {
            type: EventType.RoomRedaction,
            content: { reason: reason },
            redacts: eventId,
        }, txnId, callback);
    }

    /**
     * @param {string} roomId
     * @param {Object} content
     * @param {string} txnId Optional.
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendMessage(roomId: string, content: any, txnId: string, callback?: Callback): Promise<ISendEventResponse> {
        if (utils.isFunction(txnId)) {
            callback = txnId as any as Callback; // for legacy
            txnId = undefined;
        }
        return this.sendEvent(roomId, "m.room.message", content, txnId, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} body
     * @param {string} txnId Optional.
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendTextMessage(roomId: string, body: string, txnId?: string, callback?: Callback): Promise<ISendEventResponse> {
        const content = ContentHelpers.makeTextMessage(body);
        return this.sendMessage(roomId, content, txnId, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} body
     * @param {string} txnId Optional.
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendNotice(roomId: string, body: string, txnId?: string, callback?: Callback): Promise<ISendEventResponse> {
        const content = ContentHelpers.makeNotice(body);
        return this.sendMessage(roomId, content, txnId, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} body
     * @param {string} txnId Optional.
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendEmoteMessage(roomId: string, body: string, txnId?: string, callback?: Callback): Promise<ISendEventResponse> {
        const content = ContentHelpers.makeEmoteMessage(body);
        return this.sendMessage(roomId, content, txnId, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} url
     * @param {Object} info
     * @param {string} text
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendImageMessage(roomId: string, url: string, info?: IImageInfo, text = "Image", callback?: Callback): Promise<ISendEventResponse> {
        if (utils.isFunction(text)) {
            callback = text as any as Callback; // legacy
            text = undefined;
        }
        const content = {
            msgtype: "m.image",
            url: url,
            info: info,
            body: text,
        };
        return this.sendMessage(roomId, content, undefined, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} url
     * @param {Object} info
     * @param {string} text
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendStickerMessage(roomId: string, url: string, info?: IImageInfo, text = "Sticker", callback?: Callback): Promise<ISendEventResponse> {
        if (utils.isFunction(text)) {
            callback = text as any as Callback; // legacy
            text = undefined;
        }
        const content = {
            url: url,
            info: info,
            body: text,
        };
        return this.sendEvent(roomId, EventType.Sticker, content, undefined, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} body
     * @param {string} htmlBody
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendHtmlMessage(roomId: string, body: string, htmlBody: string, callback?: Callback): Promise<ISendEventResponse> {
        const content = ContentHelpers.makeHtmlMessage(body, htmlBody);
        return this.sendMessage(roomId, content, undefined, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} body
     * @param {string} htmlBody
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendHtmlNotice(roomId: string, body: string, htmlBody: string, callback?: Callback): Promise<ISendEventResponse> {
        const content = ContentHelpers.makeHtmlNotice(body, htmlBody);
        return this.sendMessage(roomId, content, undefined, callback);
    }

    /**
     * @param {string} roomId
     * @param {string} body
     * @param {string} htmlBody
     * @param {module:client.callback} callback Optional.
     * @return {Promise} Resolves: TODO
     * @return {module:http-api.MatrixError} Rejects: with an error response.
     */
    public sendHtmlEmote(roomId: string, body: string, htmlBody: string, callback?: Callback): Promise<ISendEventResponse> {
        const content = ContentHelpers.makeHtmlEmote(body, htmlBody);
        return this.sendMessage(roomId, content, undefined, callback);
    }

    // sendReceipt
}

