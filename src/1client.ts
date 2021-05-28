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

import url from "url";
import {EventEmitter} from "events";
import {MatrixBaseApis} from "./base-apis";
import {Filter} from "./filter";
import {SyncApi} from "./sync";
import {EventStatus, MatrixEvent} from "./models/event";
import {EventTimeline} from "./models/event-timeline";
import {SearchResult} from "./models/search-result";
import {StubStore} from "./store/stub";
import { createNewMatrixCall, MatrixCall } from "./webrtc/call";
import {CallEventHandler} from './webrtc/callEventHandler';
import * as utils from './utils';
import {sleep} from './utils';
import {
    MatrixError,
    PREFIX_MEDIA_R0,
    PREFIX_UNSTABLE,
    retryNetworkOperation,
} from "./http-api";
import {getHttpUriForMxc} from "./content-repo";
import * as ContentHelpers from "./content-helpers";
import * as olmlib from "./crypto/olmlib";
import {ReEmitter} from './ReEmitter';
import {RoomList} from './crypto/RoomList';
import {logger} from './logger';
import {Crypto, isCryptoAvailable, fixBackupKey, DeviceInfo} from './crypto';
import {decodeRecoveryKey} from './crypto/recoverykey';
import {keyFromAuthData} from './crypto/key_passphrase';
import {randomString} from './randomstring';
import {PushProcessor} from "./pushprocessor";
import {encodeBase64, decodeBase64} from "./crypto/olmlib";
import { User } from "./models/user";
import {AutoDiscovery} from "./autodiscovery";
import {DEHYDRATION_ALGORITHM} from "./crypto/dehydration";
import { IKeyBackupRoomSessions, IKeyBackupSession } from "./@types/keybackup";
import { PkDecryption } from "olm";
import { IIdentityProvider } from "../../matrix-react-sdk/src/Login";
import { IIdentityServerProvider } from "./@types/IIdentityServerProvider";
import type Request from "request";
import {MatrixScheduler} from "./scheduler";
import { ICryptoCallbacks } from "./matrix";
import {MemoryCryptoStore} from "./crypto/store/memory-crypto-store";
import {LocalStorageCryptoStore} from "./crypto/store/localStorage-crypto-store";
import {IndexedDBCryptoStore} from "./crypto/store/indexeddb-crypto-store";
import {MemoryStore} from "./store/memory";
import {LocalIndexedDBStoreBackend} from "./store/indexeddb-local-backend";
import {RemoteIndexedDBStoreBackend} from "./store/indexeddb-remote-backend";
import { SessionState } from "http2";
import { IDehydratedDevice, IDehydratedDeviceKeyInfo } from "./@types/dehydration";
import { SyncState } from "./sync.api";
import { EventTimelineSet } from "./models/event-timeline-set";
import { VerificationRequest } from "./crypto/verification/request/VerificationRequest";

export type Store = StubStore | MemoryStore | LocalIndexedDBStoreBackend | RemoteIndexedDBStoreBackend;

export type CryptoStore = MemoryCryptoStore | LocalStorageCryptoStore | IndexedDBCryptoStore;

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
                    updatePendingEventStatus(room, eventToSend, EventStatus.SENDING);
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
}

