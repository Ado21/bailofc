"use strict";
var __importDefault = (this && this.__importDefault) || function (mod: any) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeMessagesRecvSocket = void 0;

import { Boom } from '@hapi/boom';
import { randomBytes } from 'crypto';
import NodeCache from '@cacheable/node-cache';
import {
    WAProto,
    WAMessageStubType,
    WAMessageStatus,
    proto,
    Message,
    WebMessageInfo,
    PeerDataOperationRequestType
} from '../../WAProto';
import { Defaults } from '../Defaults';
import {
    WAMessage,
    WAMessageKey,
    WAMessageUpdate,
    MessageReceiptUpdate,
    ContactUpdate,
    BlocklistUpdate,
    CallEvent,
    NewsletterReaction,
    NewsletterView,
    NewsletterParticipantsUpdate,
    NewsletterSettingsUpdate,
    MexOperations,
    XWAPaths,
    NO_MESSAGE_FOUND_ERROR_TEXT,
    MISSING_KEYS_ERROR_TEXT,
    NACK_REASONS,
    KEY_BUNDLE_TYPE
} from '../Types';
import {
    decodeMessageNode,
    decryptMessageNode,
    getStatusFromReceiptType,
    getHistoryMsg,
    cleanMessage,
    delay,
    encodeBigEndian,
    encodeSignedDeviceIdentity,
    getNextPreKeys,
    xmppPreKey,
    xmppSignedPreKey,
    aesEncryptGCM,
    aesDecryptCTR,
    hkdf,
    derivePairingCodeKey,
    Curve
} from '../Utils';
import { makeMutex } from '../Utils/make-mutex';
import {
    jidNormalizedUser,
    isJidGroup,
    isJidUser,
    isJidStatusBroadcast,
    areJidsSameUser,
    jidDecode,
    isLidUser,
    S_WHATSAPP_NET,
    getBinaryNodeChild,
    getBinaryNodeChildren,
    getAllBinaryNodeChildren,
    getBinaryNodeChildBuffer,
    getCallStatusFromNode
} from '../WABinary';
import { extractGroupMetadata } from './groups';
import { makeMessagesSocket } from './messages-send';

interface MessagesRecvSocketConfig {
    logger: any;
    retryRequestDelayMs?: number;
    maxMsgRetryCount?: number;
    getMessage: (key: WAMessageKey) => Promise<WAMessage | undefined>;
    shouldIgnoreJid: (jid: string) => boolean;
    msgRetryCounterCache?: NodeCache;
    callOfferCache?: NodeCache;
    placeholderResendCache?: NodeCache;
}

interface CallOffer {
    chatId: string;
    from: string;
    id: string;
    date: Date;
    offline: boolean;
    status: string;
    isVideo?: boolean;
    isGroup?: boolean;
    groupJid?: string;
}

const makeMessagesRecvSocket = (config: MessagesRecvSocketConfig) => {
    const {
        logger,
        retryRequestDelayMs,
        maxMsgRetryCount = 5,
        getMessage,
        shouldIgnoreJid
    } = config;

    const sock = makeMessagesSocket(config);
    const {
        ev,
        authState,
        ws,
        processingMutex,
        signalRepository,
        query,
        upsertMessage,
        resyncAppState,
        groupMetadata,
        onUnexpectedError,
        assertSessions,
        sendNode,
        relayMessage,
        sendReceipt,
        uploadPreKeys,
        createParticipantNodes,
        getUSyncDevices,
        sendPeerDataOperationMessage
    } = sock;

    const retryMutex = makeMutex();
    const msgRetryCache = config.msgRetryCounterCache || new NodeCache({
        stdTTL: Defaults.DEFAULT_CACHE_TTLS.MSG_RETRY,
        useClones: false
    });
    const callOfferCache = config.callOfferCache || new NodeCache({
        stdTTL: Defaults.DEFAULT_CACHE_TTLS.CALL_OFFER,
        useClones: false
    });
    const placeholderResendCache = config.placeholderResendCache || new NodeCache({
        stdTTL: Defaults.DEFAULT_CACHE_TTLS.MSG_RETRY,
        useClones: false
    });

    let sendActiveReceipts = false;

    const sendMessageAck = async (
        { tag, attrs, content }: { tag: string; attrs: any; content?: any[] },
        errorCode?: number
    ) => {
        const stanza: any = {
            tag: 'ack',
            attrs: {
                id: attrs.id,
                to: attrs.from,
                class: tag
            }
        };

        if (errorCode) {
            stanza.attrs.error = errorCode.toString();
        }
        if (attrs.participant) stanza.attrs.participant = attrs.participant;
        if (attrs.recipient) stanza.attrs.recipient = attrs.recipient;
        if (attrs.type && (tag !== 'message' || getBinaryNodeChild({ tag, attrs, content }, 'unavailable') || errorCode !== 0)) {
            stanza.attrs.type = attrs.type;
        }
        if (tag === 'message' && getBinaryNodeChild({ tag, attrs, content }, 'unavailable')) {
            stanza.attrs.from = authState.creds.me.id;
        }

        logger.debug({ recv: { tag, attrs }, sent: stanza.attrs }, 'sent ack');
        await sendNode(stanza);
    };

    const offerCall = async (toJid: string, isVideo = false): Promise<{ callId: string; toJid: string; isVideo: boolean }> => {
        const callId = randomBytes(16).toString('hex').toUpperCase().substring(0, 64);
        const offerContent: any[] = [
            { tag: 'audio', attrs: { enc: 'opus', rate: '16000' }, content: undefined },
            { tag: 'audio', attrs: { enc: 'opus', rate: '8000' }, content: undefined }
        ];

        if (isVideo) {
            offerContent.push({
                tag: 'video',
                attrs: {
                    orientation: '0',
                    'screen_width': '1920',
                    'screen_height': '1080',
                    'device_orientation': '0',
                    enc: 'vp8',
                    dec: 'vp8',
                }
            });
        }

        offerContent.push({ tag: 'net', attrs: { medium: '3' }, content: undefined });
        offerContent.push({ tag: 'capability', attrs: { ver: '1' }, content: new Uint8Array([1, 4, 255, 131, 207, 4]) });
        offerContent.push({ tag: 'encopt', attrs: { keygen: '2' }, content: undefined });

        const encKey = randomBytes(32);
        const devices = (await getUSyncDevices([toJid], true, false))
            .map(({ user, device }) => jidEncode(user, 's.whatsapp.net', device));

        await assertSessions(devices, true);
        const { nodes: destinations, shouldIncludeDeviceIdentity } = await createParticipantNodes(devices, { call: { callKey: encKey } });

        offerContent.push({ tag: 'destination', attrs: {}, content: destinations });
        if (shouldIncludeDeviceIdentity) {
            offerContent.push({
                tag: 'device-identity',
                attrs: {},
                content: encodeSignedDeviceIdentity(authState.creds.account, true)
            });
        }

        const stanza = {
            tag: 'call',
            attrs: { to: toJid },
            content: [{
                tag: 'offer',
                attrs: {
                    'call-id': callId,
                    'call-creator': authState.creds.me.id,
                },
                content: offerContent,
            }],
        };

        await query(stanza);
        return { callId, toJid, isVideo };
    };

    const rejectCall = async (callId: string, callFrom: string) => {
        const stanza = {
            tag: 'call',
            attrs: { from: authState.creds.me.id, to: callFrom },
            content: [{
                tag: 'reject',
                attrs: {
                    'call-id': callId,
                    'call-creator': callFrom,
                    count: '0',
                },
                content: undefined,
            }],
        };
        await query(stanza);
    };

    const sendRetryRequest = async (node: any, forceIncludeKeys = false) => {
        const { fullMessage } = decodeMessageNode(node, authState.creds.me.id, authState.creds.me.lid || '');
        const { key: msgKey } = fullMessage;
        const msgId = msgKey.id;
        const key = `${msgId}:${msgKey?.participant}`;
        let retryCount = msgRetryCache.get<number>(key) || 0;

        if (retryCount >= maxMsgRetryCount) {
            logger.debug({ retryCount, msgId }, 'reached retry limit, clearing');
            msgRetryCache.del(key);
            return;
        }

        retryCount += 1;
        msgRetryCache.set(key, retryCount);

        const { account, signedPreKey, signedIdentityKey: identityKey } = authState.creds;

        if (retryCount === 1) {
            const msgId = await requestPlaceholderResend(msgKey);
            logger.debug(`sendRetryRequest: requested placeholder resend for message ${msgId}`);
        }

        const deviceIdentity = encodeSignedDeviceIdentity(account, true);

        await authState.keys.transaction(async () => {
            const receipt: any = {
                tag: 'receipt',
                attrs: {
                    id: msgId,
                    type: 'retry',
                    to: node.attrs.from
                },
                content: [
                    { tag: 'retry', attrs: { count: retryCount.toString(), id: node.attrs.id, t: node.attrs.t, v: '1' } },
                    { tag: 'registration', attrs: {}, content: encodeBigEndian(authState.creds.registrationId) }
                ]
            };

            if (node.attrs.recipient) receipt.attrs.recipient = node.attrs.recipient;
            if (node.attrs.participant) receipt.attrs.participant = node.attrs.participant;

            if (retryCount > 1 || forceIncludeKeys) {
                const { update, preKeys } = await getNextPreKeys(authState, 1);
                const [keyId] = Object.keys(preKeys);
                const key = preKeys[+keyId];

                const content = receipt.content;
                content.push({
                    tag: 'keys',
                    attrs: {},
                    content: [
                        { tag: 'type', attrs: {}, content: Buffer.from(KEY_BUNDLE_TYPE) },
                        { tag: 'identity', attrs: {}, content: identityKey.public },
                        xmppPreKey(key, +keyId),
                        xmppSignedPreKey(signedPreKey),
                        { tag: 'device-identity', attrs: {}, content: deviceIdentity }
                    ]
                });
                ev.emit('creds.update', update);
            }

            await sendNode(receipt);
            logger.info({ msgAttrs: node.attrs, retryCount }, 'sent retry receipt');
        });
    };

    const handleEncryptNotification = async (node: any) => {
        const from = node.attrs.from;
        if (from === S_WHATSAPP_NET) {
            const countChild = getBinaryNodeChild(node, 'count');
            const count = +countChild.attrs.value;
            const shouldUploadMorePreKeys = count < Defaults.MIN_PREKEY_COUNT;
            logger.debug({ count, shouldUploadMorePreKeys }, 'recv pre-key count');
            if (shouldUploadMorePreKeys) {
                await uploadPreKeys();
            }
        } else {
            const identityNode = getBinaryNodeChild(node, 'identity');
            if (identityNode) {
                logger.info({ jid: from }, 'identity changed');
            } else {
                logger.info({ node }, 'unknown encrypt notification');
            }
        }
    };

    const handleGroupNotification = (participant: string, child: any, msg: Partial<WebMessageInfo>) => {
        const participantJid = getBinaryNodeChild(child, 'participant')?.attrs?.jid || participant;

        switch (child?.tag) {
            case 'create':
                const metadata = extractGroupMetadata(child);
                msg.messageStubType = WAMessageStubType.GROUP_CREATE;
                msg.messageStubParameters = [metadata.subject];
                msg.key = { participant: metadata.owner };
                ev.emit('chats.upsert', [{ id: metadata.id, name: metadata.subject, conversationTimestamp: metadata.creation }]);
                ev.emit('groups.upsert', [{ ...metadata, author: participant }]);
                break;
            case 'ephemeral':
            case 'not_ephemeral':
                msg.message = {
                    protocolMessage: {
                        type: proto.Message.ProtocolMessage.Type.EPHEMERAL_SETTING,
                        ephemeralExpiration: +(child.attrs.expiration || 0)
                    }
                };
                break;
            case 'modify':
                const oldNumber = getBinaryNodeChildren(child, 'participant').map(p => p.attrs.jid);
                msg.messageStubParameters = oldNumber || [];
                msg.messageStubType = WAMessageStubType.GROUP_PARTICIPANT_CHANGE_NUMBER;
                break;
            case 'promote':
            case 'demote':
            case 'remove':
            case 'add':
            case 'leave':
                const stubType = `GROUP_PARTICIPANT_${child.tag.toUpperCase()}` as keyof typeof WAMessageStubType;
                msg.messageStubType = WAMessageStubType[stubType];
                const participants = getBinaryNodeChildren(child, 'participant').map(p => p.attrs.jid);
                if (participants.length === 1 && areJidsSameUser(participants[0], participant) && child.tag === 'remove') {
                    msg.messageStubType = WAMessageStubType.GROUP_PARTICIPANT_LEAVE;
                }
                msg.messageStubParameters = participants;
                break;
            case 'subject':
                msg.messageStubType = WAMessageStubType.GROUP_CHANGE_SUBJECT;
                msg.messageStubParameters = [child.attrs.subject];
                break;
            case 'description':
                const description = getBinaryNodeChild(child, 'body')?.content?.toString();
                msg.messageStubType = WAMessageStubType.GROUP_CHANGE_DESCRIPTION;
                msg.messageStubParameters = description ? [description] : undefined;
                break;
            case 'announcement':
            case 'not_announcement':
                msg.messageStubType = WAMessageStubType.GROUP_CHANGE_ANNOUNCE;
                msg.messageStubParameters = [(child.tag === 'announcement') ? 'on' : 'off'];
                break;
            case 'locked':
            case 'unlocked':
                msg.messageStubType = WAMessageStubType.GROUP_CHANGE_RESTRICT;
                msg.messageStubParameters = [(child.tag === 'locked') ? 'on' : 'off'];
                break;
            case 'invite':
                msg.messageStubType = WAMessageStubType.GROUP_CHANGE_INVITE_LINK;
                msg.messageStubParameters = [child.attrs.code];
                break;
            case 'member_add_mode':
                const addMode = child.content?.toString();
                if (addMode) {
                    msg.messageStubType = WAMessageStubType.GROUP_MEMBER_ADD_MODE;
                    msg.messageStubParameters = [addMode];
                }
                break;
            case 'membership_approval_mode':
                const approvalMode = getBinaryNodeChild(child, 'group_join');
                if (approvalMode) {
                    msg.messageStubType = WAMessageStubType.GROUP_MEMBERSHIP_JOIN_APPROVAL_MODE;
                    msg.messageStubParameters = [approvalMode.attrs.state];
                }
                break;
            case 'created_membership_requests':
                msg.messageStubType = WAMessageStubType.GROUP_MEMBERSHIP_JOIN_APPROVAL_REQUEST_NON_ADMIN_ADD;
                msg.messageStubParameters = [participantJid, 'created', child.attrs.request_method];
                break;
            case 'revoked_membership_requests':
                const isDenied = areJidsSameUser(participantJid, participant);
                msg.messageStubType = WAMessageStubType.GROUP_MEMBERSHIP_JOIN_APPROVAL_REQUEST_NON_ADMIN_ADD;
                msg.messageStubParameters = [participantJid, isDenied ? 'revoked' : 'rejected'];
                break;
        }
    };

    const handleNewsletterNotification = (id: string, node: any) => {
        const messages = getBinaryNodeChild(node, 'messages');
        const message = getBinaryNodeChild(messages, 'message');
        const serverId = message.attrs.server_id;
        const reactionsList = getBinaryNodeChild(message, 'reactions');
        const viewsList = getBinaryNodeChildren(message, 'views_count');

        if (reactionsList) {
            const reactions = getBinaryNodeChildren(reactionsList, 'reaction');
            if (reactions.length === 0) {
                ev.emit('newsletter.reaction', { id, server_id: serverId, reaction: { removed: true } } as NewsletterReaction);
            }
            reactions.forEach(item => {
                ev.emit('newsletter.reaction', {
                    id,
                    server_id: serverId,
                    reaction: { code: item.attrs.code, count: +item.attrs.count }
                } as NewsletterReaction);
            });
        }

        if (viewsList.length) {
            viewsList.forEach(item => {
                ev.emit('newsletter.view', { id, server_id: serverId, count: +item.attrs.count } as NewsletterView);
            });
        }
    };

    const handleMexNewsletterNotification = (id: string, node: any) => {
        const operation = node?.attrs.op_name as MexOperations | undefined;
        const contentStr = node?.content?.toString();
        if (!contentStr) return;
        const content = JSON.parse(contentStr);
        let contentPath: any;

        if (operation === MexOperations.PROMOTE || operation === MexOperations.DEMOTE) {
            let action: 'promote' | 'demote';
            if (operation === MexOperations.PROMOTE) {
                action = 'promote';
                contentPath = content.data[XWAPaths.PROMOTE];
            } else {
                action = 'demote';
                contentPath = content.data[XWAPaths.DEMOTE];
            }
            ev.emit('newsletter-participants.update', {
                id,
                author: contentPath.actor.pn,
                user: contentPath.user.pn,
                new_role: contentPath.user_new_role,
                action
            } as NewsletterParticipantsUpdate);
        }

        if (operation === MexOperations.UPDATE) {
            contentPath = content.data[XWAPaths.METADATA_UPDATE];
            ev.emit('newsletter-settings.update', {
                id,
                update: contentPath.thread_metadata.settings
            } as NewsletterSettingsUpdate);
        }
    };

    const processNotification = async (node: any): Promise<Partial<WebMessageInfo> | undefined> => {
        const result: Partial<WebMessageInfo> = {};
        const [child] = getAllBinaryNodeChildren(node);
        const nodeType = node.attrs.type;
        const from = jidNormalizedUser(node.attrs.from);

        switch (nodeType) {
            case 'privacy_token':
                const tokenList = getBinaryNodeChildren(child, 'token');
                for (const { attrs, content } of tokenList) {
                    const jid = attrs.jid;
                    ev.emit('chats.update', [{ id: jid, tcToken: content }] as ContactUpdate[]);
                    logger.debug({ jid }, 'got privacy token update');
                }
                break;
            case 'newsletter':
                handleNewsletterNotification(node.attrs.from, child);
                break;
            case 'mex':
                handleMexNewsletterNotification(node.attrs.from, child);
                break;
            case 'w:gp2':
                handleGroupNotification(node.attrs.participant, child, result);
                break;
            case 'mediaretry':
                const event = decodeMediaRetryNode(node);
                ev.emit('messages.media-update', [event]);
                break;
            case 'encrypt':
                await handleEncryptNotification(node);
                break;
            case 'devices':
                const devices = getBinaryNodeChildren(child, 'device');
                if (areJidsSameUser(child.attrs.jid, authState.creds.me.id)) {
                    const deviceJids = devices.map(d => d.attrs.jid);
                    logger.info({ deviceJids }, 'got my own devices');
                }
                break;
            case 'server_sync':
                const update = getBinaryNodeChild(node, 'collection');
                if (update) {
                    const name = update.attrs.name;
                    await resyncAppState([name], false);
                }
                break;
            case 'picture':
                const setPicture = getBinaryNodeChild(node, 'set');
                const delPicture = getBinaryNodeChild(node, 'delete');
                ev.emit('contacts.update', [{
                    id: from || (setPicture || delPicture)?.attrs?.hash || '',
                    imgUrl: setPicture ? 'changed' : 'removed'
                }] as ContactUpdate[]);
                if (isJidGroup(from)) {
                    const node = setPicture || delPicture;
                    result.messageStubType = WAMessageStubType.GROUP_CHANGE_ICON;
                    if (setPicture) result.messageStubParameters = [setPicture.attrs.id];
                    result.participant = node?.attrs.author;
                    result.key = { ...result.key, participant: setPicture?.attrs.author };
                }
                break;
            case 'account_sync':
                if (child.tag === 'disappearing_mode') {
                    const newDuration = +child.attrs.duration;
                    const timestamp = +child.attrs.t;
                    logger.info({ newDuration }, 'updated account disappearing mode');
                    ev.emit('creds.update', {
                        accountSettings: {
                            ...authState.creds.accountSettings,
                            defaultDisappearingMode: {
                                ephemeralExpiration: newDuration,
                                ephemeralSettingTimestamp: timestamp,
                            },
                        }
                    });
                } else if (child.tag === 'blocklist') {
                    const blocklists = getBinaryNodeChildren(child, 'item');
                    for (const { attrs } of blocklists) {
                        const blocklist = [attrs.jid];
                        const type = (attrs.action === 'block') ? 'add' : 'remove';
                        ev.emit('blocklist.update', { blocklist, type } as BlocklistUpdate);
                    }
                }
                break;
            case 'link_code_companion_reg':
                const linkCodeCompanionReg = getBinaryNodeChild(node, 'link_code_companion_reg');
                const ref = toRequiredBuffer(getBinaryNodeChildBuffer(linkCodeCompanionReg, 'link_code_pairing_ref'));
                const primaryIdentityPublicKey = toRequiredBuffer(getBinaryNodeChildBuffer(linkCodeCompanionReg, 'primary_identity_pub'));
                const primaryEphemeralPublicKeyWrapped = toRequiredBuffer(getBinaryNodeChildBuffer(linkCodeCompanionReg, 'link_code_pairing_wrapped_primary_ephemeral_pub'));
                const codePairingPublicKey = await decipherLinkPublicKey(primaryEphemeralPublicKeyWrapped);
                const companionSharedKey = Curve.sharedKey(authState.creds.pairingEphemeralKeyPair.private, codePairingPublicKey);
                const random = randomBytes(32);
                const linkCodeSalt = randomBytes(32);
                const linkCodePairingExpanded = await hkdf(companionSharedKey, 32, {
                    salt: linkCodeSalt,
                    info: 'link_code_pairing_key_bundle_encryption_key'
                });
                const encryptPayload = Buffer.concat([Buffer.from(authState.creds.signedIdentityKey.public), primaryIdentityPublicKey, random]);
                const encryptIv = randomBytes(12);
                const encrypted = aesEncryptGCM(encryptPayload, linkCodePairingExpanded, encryptIv, Buffer.alloc(0));
                const encryptedPayload = Buffer.concat([linkCodeSalt, encryptIv, encrypted]);
                const identitySharedKey = Curve.sharedKey(authState.creds.signedIdentityKey.private, primaryIdentityPublicKey);
                const identityPayload = Buffer.concat([companionSharedKey, identitySharedKey, random]);
                authState.creds.advSecretKey = (await hkdf(identityPayload, 32, { info: 'adv_secret' })).toString('base64');

                await query({
                    tag: 'iq',
                    attrs: {
                        to: S_WHATSAPP_NET,
                        type: 'set',
                        id: sock.generateMessageTag(),
                        xmlns: 'md'
                    },
                    content: [
                        {
                            tag: 'link_code_companion_reg',
                            attrs: { jid: authState.creds.me.id, stage: 'companion_finish' },
                            content: [
                                { tag: 'link_code_pairing_wrapped_key_bundle', attrs: {}, content: encryptedPayload },
                                { tag: 'companion_identity_public', attrs: {}, content: authState.creds.signedIdentityKey.public },
                                { tag: 'link_code_pairing_ref', attrs: {}, content: ref }
                            ]
                        }
                    ]
                });

                authState.creds.registered = true;
                ev.emit('creds.update', authState.creds);
                break;
        }

        if (Object.keys(result).length) return result;
    };

    async function decipherLinkPublicKey(data: Buffer | undefined): Promise<Buffer> {
        const buffer = toRequiredBuffer(data);
        const salt = buffer.slice(0, 32);
        const secretKey = await derivePairingCodeKey(authState.creds.pairingCode, salt);
        const iv = buffer.slice(32, 48);
        const payload = buffer.slice(48, 80);
        return aesDecryptCTR(payload, secretKey, iv);
    }

    function toRequiredBuffer(data: Buffer | Uint8Array | undefined): Buffer {
        if (!data) throw new Boom('Invalid buffer', { statusCode: 400 });
        return Buffer.from(data);
    }

    const willSendMessageAgain = (id: string, participant?: string): boolean => {
        const key = `${id}:${participant}`;
        const retryCount = msgRetryCache.get<number>(key) || 0;
        return retryCount < maxMsgRetryCount;
    };

    const updateSendMessageAgainCount = (id: string, participant?: string) => {
        const key = `${id}:${participant}`;
        const newValue = (msgRetryCache.get<number>(key) || 0) + 1;
        msgRetryCache.set(key, newValue);
    };

    const sendMessagesAgain = async (key: WAMessageKey, ids: string[], retryNode: any) => {
        const msgs = await Promise.all(ids.map(id => getMessage({ ...key, id })));
        const remoteJid = key.remoteJid!;
        const participant = key.participant || remoteJid;
        const sendToAll = !jidDecode(participant)?.device;

        await assertSessions([participant], true);
        if (isJidGroup(remoteJid)) {
            await authState.keys.set({ 'sender-key-memory': { [remoteJid]: null } });
        }
        logger.debug({ participant, sendToAll }, 'forced new session for retry recp');

        for (const [i, msg] of msgs.entries()) {
            if (msg) {
                updateSendMessageAgainCount(ids[i], participant);
                const msgRelayOpts: any = { messageId: ids[i] };
                if (sendToAll) {
                    msgRelayOpts.useUserDevicesCache = false;
                } else {
                    msgRelayOpts.participant = { jid: participant, count: +retryNode.attrs.count };
                }
                await relayMessage(key.remoteJid!, msg, msgRelayOpts);
            } else {
                logger.debug({ jid: key.remoteJid, id: ids[i] }, 'recv retry request, but message not available');
            }
        }
    };

    const handleReceipt = async (node: any) => {
        const { attrs, content } = node;
        const isLid = attrs.from.includes('lid');
        const isNodeFromMe = areJidsSameUser(
            attrs.participant || attrs.from,
            isLid ? authState.creds.me?.lid : authState.creds.me?.id
        );
        const remoteJid = !isNodeFromMe || isJidGroup(attrs.from) ? attrs.from : attrs.recipient;
        const fromMe = !attrs.recipient || ((attrs.type === 'retry' || attrs.type === 'sender') && isNodeFromMe);
        const key: WAMessageKey = { remoteJid, id: '', fromMe, participant: attrs.participant };

        if (shouldIgnoreJid(remoteJid) && remoteJid !== '@s.whatsapp.net') {
            logger.debug({ remoteJid }, 'ignoring receipt from jid');
            await sendMessageAck(node);
            return;
        }

        const ids = [attrs.id];
        if (Array.isArray(content)) {
            const items = getBinaryNodeChildren(content[0], 'item');
            ids.push(...items.map(i => i.attrs.id));
        }

        try {
            await Promise.all([
                processingMutex.mutex(async () => {
                    const status = getStatusFromReceiptType(attrs.type);
                    if (typeof status !== 'undefined' && (status >= WAMessageStatus.SERVER_ACK || !isNodeFromMe)) {
                        if (isJidGroup(remoteJid) || isJidStatusBroadcast(remoteJid)) {
                            if (attrs.participant) {
                                const updateKey = status === WAMessageStatus.DELIVERY_ACK ? 'receiptTimestamp' : 'readTimestamp';
                                ev.emit('message-receipt.update', ids.map(id => ({
                                    key: { ...key, id },
                                    receipt: {
                                        userJid: jidNormalizedUser(attrs.participant),
                                        [updateKey]: +attrs.t
                                    }
                                } as MessageReceiptUpdate)));
                            }
                        } else {
                            ev.emit('messages.update', ids.map(id => ({
                                key: { ...key, id },
                                update: { status }
                            } as WAMessageUpdate)));
                        }
                    }

                    if (attrs.type === 'retry') {
                        key.participant = key.participant || attrs.from;
                        const retryNode = getBinaryNodeChild(node, 'retry');
                        if (willSendMessageAgain(ids[0], key.participant)) {
                            if (key.fromMe) {
                                try {
                                    logger.debug({ attrs, key }, 'recv retry request');
                                    await sendMessagesAgain(key, ids, retryNode);
                                } catch (error: any) {
                                    logger.error({ key, ids, trace: error.stack }, 'error in sending message again');
                                }
                            } else {
                                logger.info({ attrs, key }, 'recv retry for not fromMe message');
                            }
                        } else {
                            logger.info({ attrs, key }, 'will not send message again, as sent too many times');
                        }
                    }
                })
            ]);
        } finally {
            await sendMessageAck(node);
        }
    };

    const handleNotification = async (node: any) => {
        const remoteJid = node.attrs.from;
        if (shouldIgnoreJid(remoteJid) && remoteJid !== '@s.whatsapp.net') {
            logger.debug({ remoteJid, id: node.attrs.id }, 'ignored notification');
            await sendMessageAck(node);
            return;
        }

        try {
            await Promise.all([
                processingMutex.mutex(async () => {
                    const msg = await processNotification(node);
                    if (msg) {
                        const fromMe = areJidsSameUser(node.attrs.participant || remoteJid, authState.creds.me.id);
                        msg.key = {
                            remoteJid,
                            fromMe,
                            participant: node.attrs.participant,
                            id: node.attrs.id,
                            ...(msg.key || {})
                        };
                        msg.participant = node.attrs.participant;
                        msg.messageTimestamp = +node.attrs.t;
                        const fullMsg = WAProto.WebMessageInfo.fromObject(msg);
                        await upsertMessage(fullMsg, 'append');
                    }
                })
            ]);
        } finally {
            await sendMessageAck(node);
        }
    };

    const handleMessage = async (node: any) => {
        if (shouldIgnoreJid(node.attrs.from) && node.attrs.from !== '@s.whatsapp.net') {
            logger.debug({ key: node.attrs.key }, 'ignored message');
            await sendMessageAck(node);
            return;
        }

        const encNode = getBinaryNodeChild(node, 'enc');
        if (encNode && encNode.attrs.type === 'msmsg') {
            logger.debug({ key: node.attrs.key }, 'ignored msmsg');
            await sendMessageAck(node);
            return;
        }

        let response: string | undefined;
        if (getBinaryNodeChild(node, 'unavailable') && !encNode) {
            await sendMessageAck(node);
            const { key } = decodeMessageNode(node, authState.creds.me.id, authState.creds.me.lid || '').fullMessage;
            response = await requestPlaceholderResend(key);
            if (response === 'RESOLVED') return;
            logger.debug('received unavailable message, acked and requested resend from phone');
        } else {
            if (placeholderResendCache.get(node.attrs.id)) {
                placeholderResendCache.del(node.attrs.id);
            }
        }

        const { fullMessage: msg, category, author, decrypt } = decryptMessageNode(
            node,
            authState.creds.me.id,
            authState.creds.me.lid || '',
            signalRepository,
            logger
        );

        if (response && msg.messageStubParameters?.[0] === NO_MESSAGE_FOUND_ERROR_TEXT) {
            msg.messageStubParameters = [NO_MESSAGE_FOUND_ERROR_TEXT, response];
        }

        if (msg.message?.protocolMessage?.type === proto.Message.ProtocolMessage.Type.SHARE_PHONE_NUMBER && node.attrs.sender_pn) {
            ev.emit('chats.phoneNumberShare', { lid: node.attrs.from, jid: node.attrs.sender_pn });
        }

        try {
            await Promise.all([
                processingMutex.mutex(async () => {
                    await decrypt();

                    if (msg.messageStubType === WAProto.WebMessageInfo.StubType.CIPHERTEXT) {
                        if (msg.messageStubParameters?.[0] === MISSING_KEYS_ERROR_TEXT) {
                            return sendMessageAck(node, NACK_REASONS.ParsingError);
                        }
                        retryMutex.mutex(async () => {
                            if (ws.isOpen) {
                                if (getBinaryNodeChild(node, 'unavailable')) return;
                                const encNode = getBinaryNodeChild(node, 'enc');
                                await sendRetryRequest(node, !encNode);
                                if (retryRequestDelayMs) await delay(retryRequestDelayMs);
                            } else {
                                logger.debug({ node }, 'connection closed, ignoring retry req');
                            }
                        });
                    } else {
                        let type: 'peer_msg' | 'sender' | 'inactive' | undefined;
                        if (msg.key.participant?.endsWith('@lid')) {
                            msg.key.participant = node.attrs.participant_pn || authState.creds.me.id;
                        }

                        if (isJidGroup(msg.key.remoteJid) && msg.message?.extendedTextMessage?.contextInfo?.participant?.endsWith('@lid')) {
                            const metadata = await groupMetadata(msg.key.remoteJid!);
                            const sender = msg.message.extendedTextMessage.contextInfo.participant;
                            const found = metadata.participants.find(p => p.id === sender);
                            msg.message.extendedTextMessage.contextInfo.participant = found?.jid || sender;
                        }

                        if (!isJidGroup(msg.key.remoteJid!) && isLidUser(msg.key.remoteJid!)) {
                            msg.key.remoteJid = node.attrs.sender_pn || node.attrs.peer_recipient_pn;
                        }

                        let participant = msg.key.participant;
                        if (category === 'peer') {
                            type = 'peer_msg';
                        } else if (msg.key.fromMe) {
                            type = 'sender';
                            if (isJidUser(msg.key.remoteJid)) participant = author;
                        } else if (!sendActiveReceipts) {
                            type = 'inactive';
                        }

                        await sendReceipt(msg.key.remoteJid!, participant, [msg.key.id], type);

                        const isAnyHistoryMsg = getHistoryMsg(msg.message);
                        if (isAnyHistoryMsg) {
                            const jid = jidNormalizedUser(msg.key.remoteJid!);
                            await sendReceipt(jid, undefined, [msg.key.id], 'hist_sync');
                        }
                    }

                    cleanMessage(msg, authState.creds.me.id);
                    await sendMessageAck(node);
                    await upsertMessage(msg, node.attrs.offline ? 'append' : 'notify');
                })
            ]);
        } catch (error: any) {
            logger.error({ error, node }, 'error in handling message');
        }
    };

    const fetchMessageHistory = async (
        count: number,
        oldestMsgKey: WAMessageKey,
        oldestMsgTimestamp: number
    ) => {
        if (!authState.creds.me?.id) throw new Boom('Not authenticated');
        const pdoMessage = {
            historySyncOnDemandRequest: {
                chatJid: oldestMsgKey.remoteJid,
                oldestMsgFromMe: oldestMsgKey.fromMe,
                oldestMsgId: oldestMsgKey.id,
                oldestMsgTimestampMs: oldestMsgTimestamp,
                onDemandMsgCount: count
            },
            peerDataOperationRequestType: PeerDataOperationRequestType.HISTORY_SYNC_ON_DEMAND
        };
        return sendPeerDataOperationMessage(pdoMessage);
    };

    const requestPlaceholderResend = async (messageKey: WAMessageKey): Promise<string> => {
        if (!authState.creds.me?.id) throw new Boom('Not authenticated');
        if (placeholderResendCache.get(messageKey.id)) {
            logger.debug({ messageKey }, 'already requested resend');
            return 'PENDING';
        } else {
            placeholderResendCache.set(messageKey.id, true);
        }

        await delay(5000);
        if (!placeholderResendCache.get(messageKey.id)) {
            logger.debug({ messageKey }, 'message received while resend requested');
            return 'RESOLVED';
        }

        const pdoMessage = {
            placeholderMessageResendRequest: [{ messageKey }],
            peerDataOperationRequestType: PeerDataOperationRequestType.PLACEHOLDER_MESSAGE_RESEND
        };

        setTimeout(() => {
            if (placeholderResendCache.get(messageKey.id)) {
                logger.debug({ messageKey }, 'PDO message without response after 15 seconds. Phone possibly offline');
                placeholderResendCache.del(messageKey.id);
            }
        }, 15000);

        return sendPeerDataOperationMessage(pdoMessage);
    };

    const handleCall = async (node: any) => {
        const { attrs } = node;
        const [infoChild] = getAllBinaryNodeChildren(node);
        const callId = infoChild.attrs['call-id'];
        const from = infoChild.attrs.from || infoChild.attrs['call-creator'];
        const status = getCallStatusFromNode(infoChild);

        const call: CallEvent = {
            chatId: attrs.from,
            from,
            id: callId,
            date: new Date(+attrs.t * 1000),
            offline: !!attrs.offline,
            status,
        };

        if (status === 'offer') {
            call.isVideo = !!getBinaryNodeChild(infoChild, 'video');
            call.isGroup = infoChild.attrs.type === 'group' || !!infoChild.attrs['group-jid'];
            call.groupJid = infoChild.attrs['group-jid'];
            callOfferCache.set(call.id, call as CallOffer);
        }

        const existingCall = callOfferCache.get<CallOffer>(call.id);
        if (existingCall) {
            call.isVideo = existingCall.isVideo;
            call.isGroup = existingCall.isGroup;
        }

        if (status === 'reject' || status === 'accept' || status === 'timeout' || status === 'terminate') {
            callOfferCache.del(call.id);
        }

        ev.emit('call', [call]);
        await sendMessageAck(node);
    };

    const handleBadAck = async ({ attrs }: { attrs: any }) => {
        const key = { remoteJid: attrs.from, fromMe: true, id: attrs.id, server_id: attrs.server_id };
        if (attrs.phash) {
            logger.info({ attrs }, 'received phash in ack, resending message...');
            const cacheKey = `${key.remoteJid}:${key.id}`;
            if ((msgRetryCache.get(cacheKey) || 0) >= maxMsgRetryCount) {
                logger.warn({ attrs }, 'reached max retry count, not sending message again');
                msgRetryCache.del(cacheKey);
                return;
            }
            const retryCount = msgRetryCache.get<number>(cacheKey) || 0;
            const msg = await getMessage(key);
            if (msg) {
                await relayMessage(key.remoteJid, msg, { messageId: key.id, useUserDevicesCache: false });
                msgRetryCache.set(cacheKey, retryCount + 1);
            } else {
                logger.warn({ attrs }, 'could not send message again, as it was not found');
            }
        }

        if (attrs.error) {
            logger.warn({ attrs }, 'received error in ack');
            ev.emit('messages.update', [{
                key,
                update: {
                    status: WAMessageStatus.ERROR,
                    messageStubParameters: [attrs.error]
                }
            }]);
        }
    };

    const processNodeWithBuffer = async (node: any, identifier: string, exec: (node: any, isOffline: boolean) => Promise<void>) => {
        ev.buffer();
        await exec(node, false).catch(err => onUnexpectedError(err, identifier));
        ev.flush();
    };

    const makeOfflineNodeProcessor = () => {
        const nodeProcessorMap = new Map<string, (node: any) => Promise<void>>([
            ['message', handleMessage],
            ['call', handleCall],
            ['receipt', handleReceipt],
            ['notification', handleNotification]
        ]);
        const nodes: { type: string; node: any }[] = [];
        let isProcessing = false;

        const enqueue = (type: string, node: any) => {
            nodes.push({ type, node });
            if (isProcessing) return;
            isProcessing = true;

            const promise = async () => {
                while (nodes.length && ws.isOpen) {
                    const { type, node } = nodes.shift()!;
                    const processor = nodeProcessorMap.get(type);
                    if (!processor) {
                        onUnexpectedError(new Error(`unknown offline node type: ${type}`), 'processing offline node');
                        continue;
                    }
                    await processor(node);
                }
                isProcessing = false;
            };
            promise().catch(err => onUnexpectedError(err, 'processing offline nodes'));
        };

        return { enqueue };
    };

    const offlineNodeProcessor = makeOfflineNodeProcessor();

    const processNode = (type: string, node: any, identifier: string, exec: (node: any, isOffline: boolean) => Promise<void>) => {
        const isOffline = !!node.attrs.offline;
        if (isOffline) {
            offlineNodeProcessor.enqueue(type, node);
        } else {
            processNodeWithBuffer(node, identifier, exec);
        }
    };

    ws.on('CB:message', (node) => processNode('message', node, 'processing message', handleMessage));
    ws.on('CB:call', (node) => processNode('call', node, 'handling call', handleCall));
    ws.on('CB:receipt', (node) => processNode('receipt', node, 'handling receipt', handleReceipt));
    ws.on('CB:notification', (node) => processNode('notification', node, 'handling notification', handleNotification));
    ws.on('CB:ack,class:message', (node) => handleBadAck(node).catch(err => onUnexpectedError(err, 'handling bad ack')));

    ev.on('call', ([call]) => {
        if (call.status === 'timeout' || (call.status === 'offer' && call.isGroup)) {
            const msg: Partial<WebMessageInfo> = {
                key: { remoteJid: call.chatId, id: call.id, fromMe: false },
                messageTimestamp: Math.floor(call.date.getTime() / 1000),
            };

            if (call.status === 'timeout') {
                msg.messageStubType = call.isVideo ? WAMessageStubType.CALL_MISSED_GROUP_VIDEO : WAMessageStubType.CALL_MISSED_GROUP_VOICE;
            } else {
                msg.message = { call: { callKey: Buffer.from(call.id) } };
            }

            const protoMsg = WAProto.WebMessageInfo.fromObject(msg);
            upsertMessage(protoMsg, call.offline ? 'append' : 'notify');
        }
    });

    ev.on('connection.update', ({ isOnline }) => {
        if (typeof isOnline !== 'undefined') {
            sendActiveReceipts = isOnline;
            logger.trace(`sendActiveReceipts set to "${sendActiveReceipts}"`);
        }
    });

    return {
        ...sock,
        sendMessageAck,
        sendRetryRequest,
        rejectCall,
        offerCall,
        fetchMessageHistory,
        requestPlaceholderResend,
    };
};

export { makeMessagesRecvSocket };